//go:build integration

package integration

// PAT-2171: the per-mapping rolling-release rule and the publication of the
// Chrome and Firefox lifecycle mappings. Like the PAT-2147 tests, every
// scenario uses its own random slug and identifiers, because lifecycle
// products and mappings are global tables shared with the rest of the
// package.

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/lifecycle"
)

type slcListedMapping struct {
	ID                int64  `json:"id"`
	Status            string `json:"status"`
	EOLSlug           string `json:"eol_slug"`
	RollingWindowDays *int   `json:"rolling_window_days"`
}

type slcListResp struct {
	Mappings []slcListedMapping `json:"mappings"`
}

// TestRollingMappingReport proposes, publishes and reads back rolling
// mappings through the real admin API and the real portal report: the latest
// major and the previous major inside the window read Supported, the previous
// major outside it and older majors read Unsupported, an ESR keeps its own
// dates, a mapping without the flag is unchanged, and no rolling row ever
// reads Ending within 90 days or carries a days-to-end figure.
func TestRollingMappingReport(t *testing.T) {
	sfx := randomHex(4)
	now := time.Now().UTC()
	day := 24 * time.Hour
	fetched := now.Add(-time.Hour)

	newSlug, oldSlug, esrSlug := "pat2171-new-"+sfx, "pat2171-old-"+sfx, "pat2171-esr-"+sfx
	// New: the latest major (200) shipped 10 days ago. Inside a 21 day window
	// the previous major (199) is still Supported; inside a 7 day window it is not.
	newCycles := []lifecycle.Cycle{
		{Name: "200", ReleaseDate: slcDate(now.Add(-10 * day)), EOLDate: slcDate(now.Add(4 * day)), IsEOL: slcBool(false)},
		{Name: "199", ReleaseDate: slcDate(now.Add(-40 * day)), EOLDate: slcDate(now.Add(-10 * day)), IsEOL: slcBool(true)},
		{Name: "198", ReleaseDate: slcDate(now.Add(-70 * day)), EOLDate: slcDate(now.Add(-40 * day)), IsEOL: slcBool(true)},
	}
	slcStore(t, newSlug, fetched, newCycles)
	// Old: the latest major (300) shipped 30 days ago, so the previous one (299) is past the window.
	slcStore(t, oldSlug, fetched, []lifecycle.Cycle{
		{Name: "300", ReleaseDate: slcDate(now.Add(-30 * day)), EOLDate: slcDate(now.Add(5 * day)), IsEOL: slcBool(false)},
		{Name: "299", ReleaseDate: slcDate(now.Add(-60 * day)), EOLDate: slcDate(now.Add(-30 * day)), IsEOL: slcBool(true)},
	})
	// ESR: 140 and 128 are separate is_lts cycles with their own dates.
	slcStore(t, esrSlug, fetched, []lifecycle.Cycle{
		{Name: "155", ReleaseDate: slcDate(now.Add(-3 * day)), EOLDate: slcDate(now.Add(11 * day)), IsEOL: slcBool(false)},
		{Name: "154", ReleaseDate: slcDate(now.Add(-17 * day)), EOLDate: slcDate(now.Add(-3 * day)), IsEOL: slcBool(true)},
		{Name: "140", ReleaseDate: slcDate(now.Add(-400 * day)), EOLDate: slcDate(now.Add(30 * day)), IsEOL: slcBool(false), IsLTS: true},
		{Name: "128", ReleaseDate: slcDate(now.Add(-800 * day)), EOLDate: slcDate(now.Add(-30 * day)), IsEOL: slcBool(true), IsLTS: true},
	})

	// Requests the API must refuse.
	base := func(id string) map[string]any {
		return map[string]any{"platform": "macos", "identity_kind": "macos_bundle", "identity_value": id,
			"eol_slug": newSlug, "version_rule": "major"}
	}
	with := func(id string, extra map[string]any) map[string]any {
		b := base(id)
		for k, v := range extra {
			b[k] = v
		}
		return b
	}
	for _, c := range []struct {
		name string
		body map[string]any
		want string
	}{
		{"window without rolling", with("com.pat2171.bad1"+sfx, map[string]any{"rolling_window_days": 21}), "needs rolling"},
		{"zero window", with("com.pat2171.bad2"+sfx, map[string]any{"rolling": true, "rolling_window_days": 0}), "between 1 and 90"},
		{"window over the cap", with("com.pat2171.bad3"+sfx, map[string]any{"rolling": true, "rolling_window_days": 91}), "between 1 and 90"},
		{"operating system", map[string]any{"platform": "windows", "identity_kind": "os", "identity_value": "windows",
			"eol_slug": "windows", "version_rule": "windows_build", "rolling": true}, "application mappings"},
	} {
		t.Run("refuses "+c.name, func(t *testing.T) {
			var out struct {
				Error string `json:"error"`
			}
			adminJSON(t, http.MethodPost, "/admin/lifecycle/mappings", c.body, http.StatusBadRequest, &out)
			if !strings.Contains(out.Error, c.want) {
				t.Errorf("error = %q, want one mentioning %q", out.Error, c.want)
			}
		})
	}

	type propose struct {
		id, slug string
		extra    map[string]any
		wantDays *int
	}
	i21, i7 := 21, 7
	idNew, idNarrow, idOld, idEsr, idPlain := "com.pat2171.new"+sfx, "com.pat2171.narrow"+sfx, "com.pat2171.old"+sfx,
		"com.pat2171.esr"+sfx, "com.pat2171.plain"+sfx
	for _, p := range []propose{
		{idNew, newSlug, map[string]any{"rolling": true}, &i21},                             // the default window
		{idNarrow, newSlug, map[string]any{"rolling": true, "rolling_window_days": 7}, &i7}, // its own window
		{idOld, oldSlug, map[string]any{"rolling": true}, &i21},
		{idEsr, esrSlug, map[string]any{"rolling": true}, &i21},
		{idPlain, newSlug, nil, nil}, // not rolling
	} {
		body := with(p.id, map[string]any{"eol_slug": p.slug})
		for k, v := range p.extra {
			body[k] = v
		}
		var out struct {
			Mapping slcListedMapping `json:"mapping"`
		}
		adminJSON(t, http.MethodPost, "/admin/lifecycle/mappings", body, http.StatusCreated, &out)
		id := out.Mapping.ID
		t.Cleanup(func() {
			_, _ = env.pool.Exec(context.Background(),
				`UPDATE lifecycle_mappings SET status = 'rejected', reviewed_by = 'test-cleanup', reviewed_at = now() WHERE id = $1 AND status <> 'rejected'`, id)
		})
		switch {
		case p.wantDays == nil && out.Mapping.RollingWindowDays != nil:
			t.Fatalf("%s: proposed without rolling but stored window %d", p.id, *out.Mapping.RollingWindowDays)
		case p.wantDays != nil && (out.Mapping.RollingWindowDays == nil || *out.Mapping.RollingWindowDays != *p.wantDays):
			t.Fatalf("%s: stored window = %v, want %d", p.id, out.Mapping.RollingWindowDays, *p.wantDays)
		}
		adminJSON(t, http.MethodPost, fmt.Sprintf("/admin/lifecycle/mappings/%d/publish", id), nil, http.StatusOK, nil)
	}
	var listed slcListResp
	adminJSON(t, http.MethodGet, "/admin/lifecycle/mappings?status=published", nil, http.StatusOK, &listed)
	var rollingListed int
	for _, m := range listed.Mappings {
		if strings.HasPrefix(m.EOLSlug, "pat2171-") && m.RollingWindowDays != nil {
			rollingListed++
		}
	}
	if rollingListed != 4 {
		t.Errorf("admin list shows %d published rolling mappings for this test, want 4", rollingListed)
	}

	tenant, _, _, err := createTestTenant(env.internalSrv.URL, "pat2171-"+sfx)
	if err != nil {
		t.Fatal(err)
	}
	cleanupTestTenant(t, tenant)
	email := "rolling-" + sfx + "@pat2171.example"
	mapPortalUser(t, email, tenant, http.StatusCreated)
	tok := env.idp.token(t, email)

	// One device per installation: an identity is one row per device.
	seq := 0
	install := func(id, version string) string {
		seq++
		dev := slcSeedDevice(t, tenant, fmt.Sprintf("h%d-%s", seq, sfx), "macOS", "26.0", "25A1", "", fetched)
		return slcSeedInstall(t, tenant, dev, "macos", "macos_bundle", id, "", "App "+id, version)
	}
	keyNew200, keyNew199, keyNew198 := install(idNew, "200.0.1"), install(idNew, "199.0.1"), install(idNew, "198.0.1")
	keyNarrow199 := install(idNarrow, "199.0.1")
	keyOld300, keyOld299 := install(idOld, "300.1"), install(idOld, "299.9")
	keyEsr155, keyEsr154, keyEsr140, keyEsr128 := install(idEsr, "155.0"), install(idEsr, "154.0.1"), install(idEsr, "140.9.0"), install(idEsr, "128.20.0")
	keyPlain200, keyPlain199 := install(idPlain, "200.0.1"), install(idPlain, "199.0.1")

	rep := slcGet(t, tok, "/v1/portal/reports/software/unsupported?limit=500")

	expect := func(what, key, version, state string, rolling bool) {
		t.Helper()
		r := slcFind(rep.Products, key, version)
		if r == nil {
			t.Errorf("%s: no row for %s %s", what, key, version)
			return
		}
		if r.State != state {
			t.Errorf("%s: %s %s = %s, want %s (%+v)", what, key, version, r.State, state, r)
		}
		if r.Source == nil || r.LastCheckedAt == nil {
			t.Errorf("%s: a %s row must carry its source and last checked date: %+v", what, r.State, r)
		}
		if rolling {
			if r.State == "ending_within_90_days" {
				t.Errorf("%s: a rolling mapping read Ending within 90 days", what)
			}
			if r.DaysToEOL != nil {
				t.Errorf("%s: a rolling row carries days_to_eol %d", what, *r.DaysToEOL)
			}
			if r.Note == nil || !strings.Contains(*r.Note, "release") {
				t.Errorf("%s: a rolling row should explain its basis, note = %v", what, r.Note)
			}
			if r.State == "supported" && r.EOLDate != nil {
				t.Errorf("%s: a supported rolling row shows the next-release date %s as an end date", what, *r.EOLDate)
			}
		}
	}
	expect("latest major", keyNew200, "200.0.1", "supported", true)
	expect("previous major inside the default window", keyNew199, "199.0.1", "supported", true)
	expect("older major", keyNew198, "198.0.1", "unsupported", true)
	expect("previous major outside a 7 day window", keyNarrow199, "199.0.1", "unsupported", true)
	expect("latest major, old release", keyOld300, "300.1", "supported", true)
	expect("previous major after the window", keyOld299, "299.9", "unsupported", true)
	expect("ESR sibling: latest", keyEsr155, "155.0", "supported", true)
	expect("ESR sibling: previous", keyEsr154, "154.0.1", "supported", true)

	// ESR cycles keep their own date-based state, days included.
	if r := slcFind(rep.Products, keyEsr140, "140.9.0"); r == nil || r.State != "ending_within_90_days" || r.DaysToEOL == nil ||
		*r.DaysToEOL < 29 || *r.DaysToEOL > 30 || r.Note != nil {
		t.Errorf("ESR 140 = %+v, want its own ending_within_90_days with about 30 days", r)
	}
	if r := slcFind(rep.Products, keyEsr128, "128.20.0"); r == nil || r.State != "unsupported" || r.DaysToEOL == nil || *r.DaysToEOL > -29 {
		t.Errorf("ESR 128 = %+v, want its own unsupported about 30 days ago", r)
	}

	// The same data under a mapping without the flag is unchanged.
	if r := slcFind(rep.Products, keyPlain200, "200.0.1"); r == nil || r.State != "ending_within_90_days" || r.DaysToEOL == nil ||
		*r.DaysToEOL < 3 || *r.DaysToEOL > 4 || r.Note != nil {
		t.Errorf("plain 200 = %+v, want ending_within_90_days in about 4 days and no note", r)
	}
	if r := slcFind(rep.Products, keyPlain199, "199.0.1"); r == nil || r.State != "unsupported" || r.DaysToEOL == nil || r.Note != nil {
		t.Errorf("plain 199 = %+v, want unsupported by its own date", r)
	}
}

func showInt(p *int) string {
	if p == nil {
		return "NULL"
	}
	return fmt.Sprint(*p)
}

func showStr(p *string) string {
	if p == nil {
		return "NULL"
	}
	return *p
}

func readMigration(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "migrations", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// TestBrowserLifecycleMappingsPublishedByMigration proves the state 0218 and
// 0219 leave behind, that both roll back and re-apply, and that the rollback
// order is enforced.
func TestBrowserLifecycleMappingsPublishedByMigration(t *testing.T) {
	ctx := context.Background()
	up := []string{"0218_lifecycle_rolling_release.sql", "0219_lifecycle_publish_browser_mappings.sql"}
	// Whatever happens below, leave the database as the migrations make it:
	// both forward files are idempotent.
	t.Cleanup(func() {
		for _, f := range up {
			if _, err := env.pool.Exec(ctx, readMigration(t, f)); err != nil {
				t.Errorf("restore %s: %v", f, err)
			}
		}
	})
	apply := func(name string) error {
		_, err := env.pool.Exec(ctx, readMigration(t, name))
		return err
	}

	type row struct {
		ID         int64
		Slug       string
		Status     string
		Days       *int
		ReviewedBy *string
	}
	browsers := func() []row {
		t.Helper()
		rows, err := env.pool.Query(ctx, `
			SELECT id, eol_slug, status, rolling_window_days, reviewed_by FROM lifecycle_mappings
			WHERE proposed_by = 'migration:0196' AND identity_kind <> 'os' AND eol_slug IN ('chrome', 'firefox')
			ORDER BY id`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.ID, &r.Slug, &r.Status, &r.Days, &r.ReviewedBy); err != nil {
				t.Fatal(err)
			}
			out = append(out, r)
		}
		return out
	}
	audits := func(action, actor string) int {
		t.Helper()
		var n int
		if err := env.pool.QueryRow(ctx, `
			SELECT count(*) FROM lifecycle_mapping_audit a
			JOIN lifecycle_mappings m ON m.id = a.mapping_id
			WHERE m.proposed_by = 'migration:0196' AND m.identity_kind <> 'os' AND m.eol_slug IN ('chrome', 'firefox')
			  AND a.action = $1 AND a.actor = $2`, action, actor).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	want := func(what, status string, days *int, reviewedBy *string) {
		t.Helper()
		rs := browsers()
		if len(rs) != 5 {
			t.Fatalf("%s: %d Chrome and Firefox seed mappings, want 5", what, len(rs))
		}
		for _, r := range rs {
			okDays := (days == nil && r.Days == nil) || (days != nil && r.Days != nil && *days == *r.Days)
			okBy := (reviewedBy == nil && r.ReviewedBy == nil) || (reviewedBy != nil && r.ReviewedBy != nil && *reviewedBy == *r.ReviewedBy)
			if r.Status != status || !okDays || !okBy {
				t.Errorf("%s: mapping %d (%s) = %s days=%s reviewed_by=%s; want %s days=%s reviewed_by=%s",
					what, r.ID, r.Slug, r.Status, showInt(r.Days), showStr(r.ReviewedBy), status, showInt(days), showStr(reviewedBy))
			}
		}
	}
	d21, mig := 21, "migration:0219"

	// The state the migrations leave: five browser mappings published and
	// rolling, everything else from the 0196 seed as it was.
	want("after migrate", "published", &d21, &mig)
	if n := audits("publish", "migration:0219"); n < 5 {
		t.Errorf("publish audit rows = %d, want at least 5", n)
	}
	var otherPublished, otherRolling, osRolling int
	if err := env.pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE identity_kind <> 'os' AND eol_slug NOT IN ('chrome', 'firefox') AND status = 'published'),
		       count(*) FILTER (WHERE identity_kind <> 'os' AND eol_slug NOT IN ('chrome', 'firefox') AND rolling_window_days IS NOT NULL),
		       count(*) FILTER (WHERE identity_kind = 'os' AND rolling_window_days IS NOT NULL)
		FROM lifecycle_mappings WHERE proposed_by = 'migration:0196'`).Scan(&otherPublished, &otherRolling, &osRolling); err != nil {
		t.Fatal(err)
	}
	if otherPublished != 0 || otherRolling != 0 || osRolling != 0 {
		t.Errorf("published non-browser seed rows = %d, rolling non-browser rows = %d, rolling OS rows = %d; want 0, 0, 0",
			otherPublished, otherRolling, osRolling)
	}

	// The CHECK: 1 to 90 days, applications only.
	for name, stmt := range map[string]string{
		"an OS mapping":   `UPDATE lifecycle_mappings SET rolling_window_days = 21 WHERE identity_kind = 'os'`,
		"zero days":       `UPDATE lifecycle_mappings SET rolling_window_days = 0 WHERE proposed_by = 'migration:0196' AND eol_slug = 'chrome'`,
		"91 days":         `UPDATE lifecycle_mappings SET rolling_window_days = 91 WHERE proposed_by = 'migration:0196' AND eol_slug = 'chrome'`,
		"negative window": `UPDATE lifecycle_mappings SET rolling_window_days = -1 WHERE proposed_by = 'migration:0196' AND eol_slug = 'chrome'`,
	} {
		if _, err := env.pool.Exec(ctx, stmt); err == nil {
			t.Errorf("rolling_window_days accepted %s", name)
		}
	}

	// A second forward pass changes nothing and adds no audit rows.
	published := audits("publish", "migration:0219")
	for _, f := range up {
		if err := apply(f); err != nil {
			t.Fatalf("re-apply %s: %v", f, err)
		}
	}
	want("after a second forward pass", "published", &d21, &mig)
	if n := audits("publish", "migration:0219"); n != published {
		t.Errorf("a second forward pass wrote audit rows: %d -> %d", published, n)
	}

	// 0218 cannot be rolled back under a published rolling mapping.
	if err := apply("0218_lifecycle_rolling_release_rollback.sql"); err == nil || !strings.Contains(err.Error(), "cannot roll back 0218") {
		t.Fatalf("0218 rollback under published rolling mappings: err = %v, want a refusal", err)
	}
	want("after the refused 0218 rollback", "published", &d21, &mig)

	// 0219 rolls back to proposed, audited, keeping the rolling setting.
	withdrawn := audits("withdraw", "migration:0219-rollback")
	if err := apply("0219_lifecycle_publish_browser_mappings_rollback.sql"); err != nil {
		t.Fatalf("0219 rollback: %v", err)
	}
	want("after 0219 rollback", "proposed", &d21, nil)
	if n := audits("withdraw", "migration:0219-rollback"); n != withdrawn+5 {
		t.Errorf("withdraw audit rows = %d, want %d", n, withdrawn+5)
	}
	var recorded int
	if err := env.pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version = '0219_lifecycle_publish_browser_mappings'`).Scan(&recorded); err != nil || recorded != 0 {
		t.Errorf("0219 still recorded after its rollback: n=%d err=%v", recorded, err)
	}

	// A mapping staff re-published under their own name survives a second 0219 rollback.
	if _, err := env.pool.Exec(ctx, `UPDATE lifecycle_mappings SET status = 'published', reviewed_by = 'staff@example', reviewed_at = now()
		WHERE id = (SELECT min(id) FROM lifecycle_mappings WHERE proposed_by = 'migration:0196' AND eol_slug = 'chrome' AND identity_kind <> 'os')`); err != nil {
		t.Fatal(err)
	}
	if err := apply("0219_lifecycle_publish_browser_mappings_rollback.sql"); err != nil {
		t.Fatalf("second 0219 rollback: %v", err)
	}
	var staffPublished int
	if err := env.pool.QueryRow(ctx, `SELECT count(*) FROM lifecycle_mappings WHERE reviewed_by = 'staff@example' AND status = 'published'`).Scan(&staffPublished); err != nil || staffPublished != 1 {
		t.Errorf("a staff-published mapping was withdrawn by the 0219 rollback: n=%d err=%v", staffPublished, err)
	}
	if _, err := env.pool.Exec(ctx, `UPDATE lifecycle_mappings SET status = 'proposed', reviewed_by = NULL, reviewed_at = NULL WHERE reviewed_by = 'staff@example'`); err != nil {
		t.Fatal(err)
	}

	// Forward 0219 publishes again; then the full down and up.
	if err := apply(up[1]); err != nil {
		t.Fatalf("0219 forward: %v", err)
	}
	want("after 0219 forward", "published", &d21, &mig)
	if err := apply("0219_lifecycle_publish_browser_mappings_rollback.sql"); err != nil {
		t.Fatal(err)
	}
	if err := apply("0218_lifecycle_rolling_release_rollback.sql"); err != nil {
		t.Fatalf("0218 rollback after 0219: %v", err)
	}
	var columns int
	if err := env.pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns
		WHERE table_name = 'lifecycle_mappings' AND column_name = 'rolling_window_days'`).Scan(&columns); err != nil || columns != 0 {
		t.Errorf("rolling_window_days still present after the 0218 rollback: n=%d err=%v", columns, err)
	}
	for _, f := range up {
		if err := apply(f); err != nil {
			t.Fatalf("re-apply %s after full rollback: %v", f, err)
		}
	}
	want("after full down and up", "published", &d21, &mig)
}
