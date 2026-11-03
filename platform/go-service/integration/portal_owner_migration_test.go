//go:build integration

package integration

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"patched.im/api/internal/db"
)

// Execute the actual 0229 SQL, including its transaction, against synthetic
// catalogue drift. The journal alone must never authorise a schema replacement.
func TestPortalOwnerMigrationSchemaContract(t *testing.T) {
	ctx := context.Background()
	name := "pat1883_" + randomHex(4) + "_test"
	if _, err := env.pool.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := env.pool.Exec(ctx, "DROP DATABASE "+name+" WITH (FORCE)"); err != nil {
			t.Error(err)
		}
	}()
	u, err := url.Parse(os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	pool, err := db.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	read := func(name string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("..", "migrations", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	forward, rollback := read("0229_portal_owner_role.sql"), read("0229_portal_owner_role_rollback.sql")
	exec := func(t *testing.T, sql string) {
		t.Helper()
		if _, err := conn.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	reset := func(t *testing.T) {
		exec(t, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;
   CREATE TABLE schema_migrations (version text PRIMARY KEY, applied_at timestamptz DEFAULT now());
   CREATE TABLE tenants (id int PRIMARY KEY, name text); INSERT INTO tenants VALUES (1, 'synthetic');
   CREATE TABLE portal_users (email text PRIMARY KEY, role text CHECK (role IN ('admin','viewer')), disabled_at timestamptz);
   INSERT INTO portal_users VALUES ('synthetic@example.invalid','viewer',NULL);
   CREATE TABLE feedback (id int PRIMARY KEY, reporter_role text CHECK (reporter_role IN ('viewer','admin')));
   INSERT INTO feedback VALUES (1,'viewer');`)
	}
	snapshot := func(t *testing.T) string {
		t.Helper()
		var s string
		err := conn.QueryRow(ctx, `SELECT jsonb_build_object(
   'columns', (SELECT jsonb_agg(to_jsonb(c) ORDER BY table_name,ordinal_position) FROM information_schema.columns c WHERE table_schema='public'),
   'checks', (SELECT jsonb_agg(jsonb_build_array(conrelid::regclass::text,conname,pg_get_constraintdef(oid),convalidated) ORDER BY conrelid::regclass::text,conname) FROM pg_constraint WHERE connamespace='public'::regnamespace AND contype='c'),
   'tenants', (SELECT jsonb_agg(to_jsonb(t)) FROM tenants t),
   'users', (SELECT jsonb_agg(to_jsonb(p)) FROM portal_users p),
   'feedback', (SELECT jsonb_agg(to_jsonb(f)) FROM feedback f),
   'journal', (SELECT jsonb_agg(to_jsonb(m) ORDER BY version) FROM schema_migrations m))::text`).Scan(&s)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	t.Run("forward_replay_rollback_reforward", func(t *testing.T) {
		reset(t)
		exec(t, forward)
		once := snapshot(t)
		exec(t, forward)
		if once != snapshot(t) {
			t.Fatal("replay changed schema, rows or journal")
		}
		exec(t, rollback)
		var gone bool
		if err := conn.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM schema_migrations) AND NOT EXISTS(SELECT 1 FROM information_schema.columns WHERE column_name IN ('created_via','disabled_by'))`).Scan(&gone); err != nil || !gone {
			t.Fatalf("rollback columns/journal: %v %v", gone, err)
		}
		exec(t, forward)
	})
	cases := []struct{ name, sql, reason string }{
		{"created_via_nullable", "ALTER TABLE tenants ALTER COLUMN created_via DROP NOT NULL", "created_via column"},
		{"created_via_default", "ALTER TABLE tenants ALTER COLUMN created_via SET DEFAULT 'self_service'", "created_via column"},
		{"created_via_no_default", "ALTER TABLE tenants ALTER COLUMN created_via DROP DEFAULT", "created_via column"},
		{"created_via_varchar", "ALTER TABLE tenants ALTER COLUMN created_via TYPE varchar(20)", "created_via column"},
		{"created_via_integer", "ALTER TABLE tenants DROP CONSTRAINT tenants_created_via_check; ALTER TABLE tenants ALTER COLUMN created_via DROP DEFAULT; ALTER TABLE tenants ALTER COLUMN created_via TYPE integer USING 1", "created_via column"},
		{"created_via_no_check", "ALTER TABLE tenants DROP CONSTRAINT tenants_created_via_check", "created_via CHECK"},
		{"created_via_wrong_check", "ALTER TABLE tenants DROP CONSTRAINT tenants_created_via_check; ALTER TABLE tenants ADD CONSTRAINT tenants_created_via_check CHECK (created_via IN ('operator','self_service','other'))", "created_via CHECK"},
		{"created_via_unvalidated", "ALTER TABLE tenants DROP CONSTRAINT tenants_created_via_check; ALTER TABLE tenants ADD CONSTRAINT tenants_created_via_check CHECK (created_via IN ('operator','self_service')) NOT VALID", "created_via CHECK"},
		{"created_via_noinherit", "ALTER TABLE tenants DROP CONSTRAINT tenants_created_via_check; ALTER TABLE tenants ADD CONSTRAINT tenants_created_via_check CHECK (created_via IN ('operator','self_service')) NO INHERIT", "created_via CHECK"},
		{"created_via_extra_check", "ALTER TABLE tenants ADD CHECK (created_via <> 'other')", "created_via CHECK"},
		{"disabled_by_varchar", "ALTER TABLE portal_users ALTER COLUMN disabled_by TYPE varchar(20)", "disabled_by column"},
		{"disabled_by_integer", "ALTER TABLE portal_users DROP CONSTRAINT portal_users_disabled_by_check; ALTER TABLE portal_users ALTER COLUMN disabled_by TYPE integer USING NULL::integer", "disabled_by column"},
		{"disabled_by_default", "ALTER TABLE portal_users ALTER COLUMN disabled_by SET DEFAULT 'operator'", "disabled_by column"},
		{"disabled_by_notnull", "UPDATE portal_users SET disabled_at=now(), disabled_by='operator'; ALTER TABLE portal_users ALTER COLUMN disabled_by SET NOT NULL", "disabled_by column"},
		{"disabled_by_no_check", "ALTER TABLE portal_users DROP CONSTRAINT portal_users_disabled_by_check", "disabled_by CHECK"},
		{"disabled_by_wrong_check", "ALTER TABLE portal_users DROP CONSTRAINT portal_users_disabled_by_check; ALTER TABLE portal_users ADD CONSTRAINT portal_users_disabled_by_check CHECK (disabled_by IN ('operator','owner'))", "disabled_by CHECK"},
		{"disabled_by_extra_check", "ALTER TABLE portal_users ADD CHECK (disabled_by <> 'other')", "disabled_by CHECK"},
		{"disabled_by_unvalidated", "ALTER TABLE portal_users DROP CONSTRAINT portal_users_disabled_by_check; ALTER TABLE portal_users ADD CONSTRAINT portal_users_disabled_by_check CHECK (disabled_by IS NULL OR (disabled_by IN ('operator','owner') AND disabled_at IS NOT NULL)) NOT VALID", "disabled_by CHECK"},
		{"created_via_missing", "ALTER TABLE tenants DROP COLUMN created_via", "created_via column"},
		{"disabled_by_missing", "ALTER TABLE portal_users DROP COLUMN disabled_by", "disabled_by column"},
	}
	reject := func(t *testing.T, reason string) {
		t.Helper()
		before := snapshot(t)
		_, err := conn.Exec(ctx, forward)
		// A failed multi-statement migration leaves its transaction aborted. Roll it
		// back on the same connection before observing preservation.
		exec(t, "ROLLBACK")
		if err == nil || !strings.Contains(err.Error(), "0229: "+reason) {
			t.Fatalf("wanted invariant-specific refusal %q, got %v", reason, err)
		}
		if before != snapshot(t) {
			t.Fatal("failed migration changed prior catalogue, rows or journal")
		}
	}
	for _, tc := range cases {
		t.Run("journalled_"+tc.name, func(t *testing.T) { reset(t); exec(t, forward); exec(t, tc.sql); reject(t, tc.reason) })
	}
	for _, tc := range []struct{ name, sql, reason string }{
		{"created_via_compatible", "ALTER TABLE tenants ADD COLUMN created_via text NOT NULL DEFAULT 'operator' CHECK (created_via IN ('operator','self_service'))", "unexpected unjournalled tenants.created_via"},
		{"created_via_integer", "ALTER TABLE tenants ADD COLUMN created_via integer", "unexpected unjournalled tenants.created_via"},
		{"disabled_by_text", "ALTER TABLE portal_users ADD COLUMN disabled_by text", "unexpected unjournalled portal_users.disabled_by"},
		{"disabled_by_integer", "ALTER TABLE portal_users ADD COLUMN disabled_by integer", "unexpected unjournalled portal_users.disabled_by"},
	} {
		t.Run("unjournalled_"+tc.name, func(t *testing.T) { reset(t); exec(t, tc.sql); reject(t, tc.reason) })
	}
}
