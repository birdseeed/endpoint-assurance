//go:build unix

package handlers

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/sys/unix"
)

func TestPurgeCommitOutcomeClassification(t *testing.T) {
	if !purgeCommitDefinitelyRolledBack(pgx.ErrTxCommitRollback) {
		t.Fatal("definite rollback was classified as ambiguous")
	}
	if !purgeCommitDefinitelyRolledBack(errors.Join(errors.New("wrapped"), pgx.ErrTxCommitRollback)) {
		t.Fatal("wrapped definite rollback was classified as ambiguous")
	}
	if purgeCommitDefinitelyRolledBack(errors.New("connection lost awaiting commit acknowledgement")) {
		t.Fatal("ambiguous commit error was classified as a rollback")
	}
	cases := []struct {
		code string
		want bool
	}{
		{"40001", true}, {"40002", true}, {"40P01", true},
		{"23505", true}, {"23514", true},
		{"40003", false}, {"40P02", false}, {"08006", false},
	}
	for _, tc := range cases {
		if got := purgeCommitDefinitelyRolledBack(&pgconn.PgError{Code: tc.code}); got != tc.want {
			t.Errorf("SQLSTATE %s definite rollback=%v, want %v", tc.code, got, tc.want)
		}
	}
}

func TestTenantPurgeDBTimeoutConfiguration(t *testing.T) {
	t.Setenv("TENANT_PURGE_DB_TIMEOUT", "7m30s")
	if got := tenantPurgeDBTimeout(); got != 7*time.Minute+30*time.Second {
		t.Fatalf("configured timeout=%s", got)
	}
	t.Setenv("TENANT_PURGE_DB_TIMEOUT", "invalid")
	if got := tenantPurgeDBTimeout(); got != defaultTenantPurgeDBTimeout {
		t.Fatalf("invalid configuration did not use default: %s", got)
	}
}

const purgeTestTenant = "11111111-2222-4333-8444-555555555555"

func purgeTempRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func makeAssessmentTree(t *testing.T, root string) string {
	t.Helper()
	tenantDir := filepath.Join(root, "assessments", purgeTestTenant)
	if err := os.MkdirAll(filepath.Join(tenantDir, "artifact"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tenantDir, "artifact", "report.pdf"), []byte("customer bytes"), 0640); err != nil {
		t.Fatal(err)
	}
	return tenantDir
}

func TestQuarantineAssessmentArtifactsAbsentDirectory(t *testing.T) {
	root := purgeTempRoot(t)
	q, err := quarantineAssessmentArtifacts(root, purgeTestTenant, false)
	if err != nil || q != nil {
		t.Fatalf("absent directory: q=%v err=%v", q, err)
	}
}

func TestQuarantineAssessmentArtifactsMissingHierarchyFailsWhenMetadataExists(t *testing.T) {
	root := purgeTempRoot(t)
	if _, err := quarantineAssessmentArtifacts(root, purgeTestTenant, true); err == nil || !strings.Contains(err.Error(), "hierarchy is absent") {
		t.Fatalf("missing hierarchy with DB metadata was accepted: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "assessments"), 0750); err != nil {
		t.Fatal(err)
	}
	if _, err := quarantineAssessmentArtifacts(root, purgeTestTenant, true); err == nil || !strings.Contains(err.Error(), "tenant directory is absent") {
		t.Fatalf("missing tenant directory with DB metadata was accepted: %v", err)
	}
}

func TestQuarantineAssessmentArtifactsRejectsSymlinkedRootComponent(t *testing.T) {
	actual := purgeTempRoot(t)
	parent := purgeTempRoot(t)
	linked := filepath.Join(parent, "linked-root")
	if err := os.Symlink(actual, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := quarantineAssessmentArtifacts(linked, purgeTestTenant, false); err == nil {
		t.Fatal("symlinked REPORT_STORAGE_ROOT component was followed")
	}
	if err := validateAssessmentStorageRoot(linked, false); err == nil {
		t.Fatal("assessment_storage health accepted symlinked root")
	}
}

func TestAssessmentStorageHealthRejectsMissingRoot(t *testing.T) {
	missing := filepath.Join(purgeTempRoot(t), "missing")
	if err := validateAssessmentStorageRoot(missing, false); err == nil {
		t.Fatal("assessment_storage health accepted missing root")
	}
}

func TestAssessmentStorageHealthMissingHierarchyReflectsMetadata(t *testing.T) {
	root := purgeTempRoot(t)
	if err := validateAssessmentStorageRoot(root, false); err != nil {
		t.Fatalf("empty installation with no assessment metadata was unhealthy: %v", err)
	}
	if err := validateAssessmentStorageRoot(root, true); err == nil || !strings.Contains(err.Error(), "artifacts exist in database") {
		t.Fatalf("missing hierarchy with assessment metadata was healthy: %v", err)
	}
}

func TestAssessmentStorageHealthRejectsPermissionsAndCrossDevice(t *testing.T) {
	root := unix.Stat_t{Uid: 501, Dev: 10, Mode: unix.S_IFDIR | 0750}
	cases := []struct {
		name string
		stat unix.Stat_t
		want error
	}{
		{"writable", unix.Stat_t{Uid: 501, Dev: 10, Mode: unix.S_IFDIR | 0777}, unix.EPERM},
		{"wrong-owner", unix.Stat_t{Uid: 502, Dev: 10, Mode: unix.S_IFDIR | 0750}, unix.EPERM},
		{"cross-device", unix.Stat_t{Uid: 501, Dev: 11, Mode: unix.S_IFDIR | 0750}, unix.EXDEV},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAssessmentStorageComponent("test", root, tc.stat)
			if err == nil {
				t.Fatal("unsafe storage component was accepted")
			}
			if tc.want == unix.EXDEV && !errors.Is(err, unix.EXDEV) {
				t.Fatalf("cross-device failure did not expose EXDEV: %v", err)
			}
		})
	}
	for _, tc := range cases {
		t.Run("quarantine-"+tc.name, func(t *testing.T) {
			err := validateAssessmentQuarantineBoundary(root, tc.stat)
			if err == nil {
				t.Fatal("unsafe quarantine boundary was accepted")
			}
			if tc.want == unix.EXDEV && !errors.Is(err, unix.EXDEV) {
				t.Fatalf("cross-device failure did not expose EXDEV: %v", err)
			}
		})
	}
}

func TestQuarantineAssessmentArtifactsRejectsPathLikeTenantID(t *testing.T) {
	root := purgeTempRoot(t)
	if _, err := quarantineAssessmentArtifacts(root, "../outside", false); err == nil {
		t.Fatal("path-like tenant ID was accepted")
	}
}

func TestQuarantineAssessmentArtifactsSuccessDoesNotFollowLinks(t *testing.T) {
	root := purgeTempRoot(t)
	tenantDir := makeAssessmentTree(t, root)
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(tenantDir, "artifact", "outside-link")); err != nil {
		t.Fatal(err)
	}

	q, err := quarantineAssessmentArtifacts(root, purgeTestTenant, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(tenantDir); !os.IsNotExist(err) {
		t.Fatalf("served tenant directory remains after quarantine: %v", err)
	}
	residue := filepath.Join(root, q.residue())
	if err := q.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(outside); err != nil || string(got) != "keep" {
		t.Fatalf("cleanup followed symlink outside quarantine: %q %v", got, err)
	}
	if _, err := os.Lstat(residue); !os.IsNotExist(err) {
		t.Fatalf("quarantine residue remains: %v", err)
	}
}

func TestQuarantineAssessmentArtifactsRejectsSymlinkAndNonDirectory(t *testing.T) {
	for _, kind := range []string{"symlink", "file"} {
		t.Run(kind, func(t *testing.T) {
			root := purgeTempRoot(t)
			if err := os.Mkdir(filepath.Join(root, "assessments"), 0750); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(root, "assessments", purgeTestTenant)
			if kind == "symlink" {
				if err := os.Symlink(t.TempDir(), target); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(target, []byte("not a directory"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := quarantineAssessmentArtifacts(root, purgeTestTenant, true); err == nil {
				t.Fatal("unsafe source was accepted")
			}
		})
	}
}

func TestQuarantineAssessmentArtifactsRejectsSymlinkQuarantine(t *testing.T) {
	root := purgeTempRoot(t)
	makeAssessmentTree(t, root)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, assessmentQuarantineDir)); err != nil {
		t.Fatal(err)
	}
	if _, err := quarantineAssessmentArtifacts(root, purgeTestTenant, true); err == nil || !strings.Contains(err.Error(), "quarantine") {
		t.Fatalf("symlink quarantine was not rejected: %v", err)
	}
}

func TestQuarantineAssessmentArtifactsRejectsWritableQuarantine(t *testing.T) {
	root := purgeTempRoot(t)
	makeAssessmentTree(t, root)
	quarantine := filepath.Join(root, assessmentQuarantineDir)
	if err := os.Mkdir(quarantine, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(quarantine, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := quarantineAssessmentArtifacts(root, purgeTestTenant, true); err == nil || !strings.Contains(err.Error(), "unsafe ownership or mode") {
		t.Fatalf("writable quarantine was not rejected: %v", err)
	}
}

func TestQuarantineCreationRaceIsRejectedWithoutAdoptingOrChmoddingBoundary(t *testing.T) {
	root := purgeTempRoot(t)
	tenantDir := makeAssessmentTree(t, root)
	originalMkdirat := assessmentQuarantineMkdirat
	assessmentQuarantineMkdirat = func(rootFD int, name string, _ uint32) error {
		if err := unix.Mkdirat(rootFD, name, 0700); err != nil {
			return err
		}
		if err := unix.Fchmodat(rootFD, name, 0777, 0); err != nil {
			return err
		}
		return unix.EEXIST
	}
	t.Cleanup(func() { assessmentQuarantineMkdirat = originalMkdirat })

	if _, err := quarantineAssessmentArtifacts(root, purgeTestTenant, true); err == nil || !strings.Contains(err.Error(), "appeared concurrently") {
		t.Fatalf("raced quarantine boundary was adopted: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(tenantDir, "artifact", "report.pdf")); err != nil || string(got) != "customer bytes" {
		t.Fatalf("customer bytes moved during rejected boundary race: %q %v", got, err)
	}
	info, err := os.Stat(filepath.Join(root, assessmentQuarantineDir))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0022 == 0 {
		t.Fatalf("raced boundary was unexpectedly chmodded: %o", info.Mode().Perm())
	}
}

func TestNewQuarantineBoundaryFsyncFailurePreventsCustomerByteMove(t *testing.T) {
	root := purgeTempRoot(t)
	tenantDir := makeAssessmentTree(t, root)
	originalFsync := assessmentStorageRootFsync
	assessmentStorageRootFsync = func(int) error { return unix.EIO }
	t.Cleanup(func() { assessmentStorageRootFsync = originalFsync })

	if _, err := quarantineAssessmentArtifacts(root, purgeTestTenant, true); !errors.Is(err, unix.EIO) {
		t.Fatalf("boundary fsync error = %v, want EIO", err)
	}
	if got, err := os.ReadFile(filepath.Join(tenantDir, "artifact", "report.pdf")); err != nil || string(got) != "customer bytes" {
		t.Fatalf("customer bytes moved before boundary durability: %q %v", got, err)
	}
	if info, err := os.Stat(filepath.Join(root, assessmentQuarantineDir)); err != nil || info.Mode().Perm()&0022 != 0 {
		t.Fatalf("failed durability left an unsafe boundary: mode=%v err=%v", info, err)
	}
}

func TestQuarantineAssessmentArtifactsRefusesOpenRenameReplacementRace(t *testing.T) {
	root := purgeTempRoot(t)
	tenantDir := makeAssessmentTree(t, root)
	originalMoved := tenantDir + ".original"
	q, err := quarantineAssessmentArtifactsWithHook(root, purgeTestTenant, true, func() {
		if err := os.Rename(tenantDir, originalMoved); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(tenantDir, 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tenantDir, "replacement"), []byte("do not delete"), 0600); err != nil {
			t.Fatal(err)
		}
	})
	if err == nil || q == nil || q.residue() == "" {
		t.Fatalf("replacement race accepted: q=%v err=%v", q, err)
	}
	if _, statErr := os.Lstat(tenantDir); !os.IsNotExist(statErr) {
		t.Fatalf("unverified replacement was republished: %v", statErr)
	}
	matches, globErr := filepath.Glob(filepath.Join(root, assessmentQuarantineDir, purgeTestTenant+"-*"))
	if globErr != nil || len(matches) != 1 {
		t.Fatalf("unverified replacement was not retained in quarantine: %v %v", matches, globErr)
	}
	if got, readErr := os.ReadFile(filepath.Join(matches[0], "replacement")); readErr != nil || string(got) != "do not delete" {
		t.Fatalf("quarantined replacement changed: %q %v", got, readErr)
	}
	if _, statErr := os.Stat(filepath.Join(originalMoved, "artifact", "report.pdf")); statErr != nil {
		t.Fatalf("original directory identity was lost: %v", statErr)
	}
}

func TestQuarantineAssessmentArtifactsRestoreAfterDatabaseFailure(t *testing.T) {
	root := purgeTempRoot(t)
	tenantDir := makeAssessmentTree(t, root)
	q, err := quarantineAssessmentArtifacts(root, purgeTestTenant, true)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate DELETE/COMMIT failure: the handler invokes Restore before
	// returning an error while the database transaction rolls back.
	if err := q.Restore(); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(tenantDir, "artifact", "report.pdf")); err != nil || string(got) != "customer bytes" {
		t.Fatalf("artifact was not restored: %q %v", got, err)
	}
	if q.residue() != "" {
		t.Fatalf("restore still reports nonexistent residue: %q", q.residue())
	}
}

func TestQuarantineRestoreRevalidatesAssessmentBoundaryPermissions(t *testing.T) {
	root := purgeTempRoot(t)
	makeAssessmentTree(t, root)
	q, err := quarantineAssessmentArtifacts(root, purgeTestTenant, true)
	if err != nil {
		t.Fatal(err)
	}
	assessments := filepath.Join(root, "assessments")
	originalAssessments := assessments + ".original"
	if err := os.Rename(assessments, originalAssessments); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(assessments, 0500); err != nil {
		t.Fatal(err)
	}
	if err := q.Restore(); err == nil || !strings.Contains(err.Error(), "incompatible ownership or permissions") {
		t.Fatalf("restore accepted an untrusted replacement assessment boundary: %v", err)
	}
	if q.residue() == "" {
		t.Fatal("restore rejection lost the quarantine residue")
	}
	if err := os.Remove(assessments); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(originalAssessments, assessments); err != nil {
		t.Fatal(err)
	}
	if err := q.Restore(); err != nil {
		t.Fatalf("restore after repairing boundary: %v", err)
	}
}

func TestQuarantineCleanupRevalidatesQuarantineBoundaryPermissions(t *testing.T) {
	root := purgeTempRoot(t)
	makeAssessmentTree(t, root)
	q, err := quarantineAssessmentArtifacts(root, purgeTestTenant, true)
	if err != nil {
		t.Fatal(err)
	}
	boundary := filepath.Join(root, assessmentQuarantineDir)
	originalBoundary := boundary + ".original"
	if err := os.Rename(boundary, originalBoundary); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(boundary, 0500); err != nil {
		t.Fatal(err)
	}
	if err := q.Cleanup(); err == nil || !strings.Contains(err.Error(), "unsafe ownership or mode") {
		t.Fatalf("cleanup accepted an untrusted replacement quarantine boundary: %v", err)
	}
	if q.residue() == "" {
		t.Fatal("cleanup rejection lost the quarantine residue")
	}
	if err := os.Remove(boundary); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(originalBoundary, boundary); err != nil {
		t.Fatal(err)
	}
	if err := q.Cleanup(); err != nil {
		t.Fatalf("cleanup after repairing boundary: %v", err)
	}
}

func TestQuarantineCleanupRefusesReplacementAndLeavesExplicitResidue(t *testing.T) {
	root := purgeTempRoot(t)
	makeAssessmentTree(t, root)
	q, err := quarantineAssessmentArtifacts(root, purgeTestTenant, true)
	if err != nil {
		t.Fatal(err)
	}
	residue := filepath.Join(root, q.residue())
	original := residue + ".original"
	if err := os.Rename(residue, original); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(residue, 0700); err != nil {
		t.Fatal(err)
	}
	if err := q.Cleanup(); err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("cleanup did not refuse replacement residue: %v", err)
	}
	if _, err := os.Stat(residue); err != nil {
		t.Fatalf("explicit cleanup-pending residue disappeared: %v", err)
	}
}

func TestQuarantineCleanupFsyncFailureDoesNotReportDeletedResidue(t *testing.T) {
	root := purgeTempRoot(t)
	makeAssessmentTree(t, root)
	q, err := quarantineAssessmentArtifacts(root, purgeTestTenant, true)
	if err != nil {
		t.Fatal(err)
	}
	residue := filepath.Join(root, q.residue())
	originalFsync := assessmentQuarantineFsync
	assessmentQuarantineFsync = func(int) error { return unix.EIO }
	t.Cleanup(func() { assessmentQuarantineFsync = originalFsync })

	if err := q.Cleanup(); !errors.Is(err, unix.EIO) {
		t.Fatalf("cleanup fsync error = %v, want EIO", err)
	}
	if q.residue() != "" {
		t.Fatalf("cleanup reported deleted residue: %q", q.residue())
	}
	if _, err := os.Lstat(residue); !os.IsNotExist(err) {
		t.Fatalf("residue still exists after successful removal: %v", err)
	}
}

func TestAssessmentPurgeRollbackPreservesHardenedAuditTriggerSearchPath(t *testing.T) {
	rollback, err := os.ReadFile("../../migrations/0109_assessment_artifact_purge_anonymisation_rollback.sql")
	if err != nil {
		t.Fatal(err)
	}
	function := `CREATE OR REPLACE FUNCTION assessment_artifact_audit_append_only()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$`
	if !strings.Contains(string(rollback), function) {
		t.Fatal("0109 rollback recreated assessment audit trigger function without hardened search_path")
	}
	anonymizer := `CREATE OR REPLACE FUNCTION anonymize_tenant_audit_before_purge() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$`
	if !strings.Contains(string(rollback), anonymizer) {
		t.Fatal("0109 rollback recreated tenant purge anonymizer without hardened search_path")
	}
}

func TestAssessmentPurgeMigrationUsesDurableRollbackMarker(t *testing.T) {
	forward, err := os.ReadFile("../../migrations/0109_assessment_artifact_purge_anonymisation.sql")
	if err != nil {
		t.Fatal(err)
	}
	rollback, err := os.ReadFile("../../migrations/0109_assessment_artifact_purge_anonymisation_rollback.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"ADD COLUMN IF NOT EXISTS tenant_purge_anonymized_at TIMESTAMPTZ",
		"OLD.tenant_purge_anonymized_at IS NULL",
		"NEW.tenant_purge_anonymized_at IS NOT DISTINCT FROM transaction_timestamp()",
		"tenant_purge_anonymized_at = transaction_timestamp()",
	} {
		if !strings.Contains(string(forward), required) {
			t.Fatalf("0109 forward migration does not pin durable purge marker behavior %q", required)
		}
	}
	if !strings.Contains(string(rollback), "WHERE tenant_purge_anonymized_at IS NOT NULL") {
		t.Fatal("0109 rollback does not refuse based on the durable purge marker")
	}
	if strings.Contains(string(rollback), "WHERE actor IS NULL AND recipient_email IS NULL AND token_id IS NULL") {
		t.Fatal("0109 rollback still infers purge history from nullable row shape")
	}
	if !strings.Contains(string(rollback), "DROP COLUMN tenant_purge_anonymized_at") {
		t.Fatal("0109 rollback does not remove the unapplied marker column")
	}
}

// PAT-1512: the purge transaction's rollback deadline must come from the same
// source as its commit deadline. It was a hardcoded 5*time.Second against a
// commit path that honoured TENANT_PURGE_DB_TIMEOUT (default 5m), so on
// exactly the large-tenant purge the longer timeout exists for, the unwinding
// transaction could expire while the commit would not have.
//
// Asserted on the effective deadline rather than on source text, so that
// rewriting how the timeout is obtained cannot quietly pass a check that only
// pattern-matched the old call.
func TestPurgeRollbackDeadlineTracksTheCommitDeadline(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  string
		want time.Duration
	}{
		{name: "default", env: "", want: defaultTenantPurgeDBTimeout},
		{name: "configured", env: "90s", want: 90 * time.Second},
		{name: "invalid falls back", env: "not-a-duration", want: defaultTenantPurgeDBTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TENANT_PURGE_DB_TIMEOUT", tc.env)

			before := time.Now()
			ctx, cancel := newPurgeRollbackContext()
			defer cancel()

			deadline, ok := ctx.Deadline()
			if !ok {
				t.Fatal("purge rollback context has no deadline; an unwind that can run unbounded is as bad as one that expires early")
			}
			got := deadline.Sub(before)
			// Generous epsilon: this asserts which timeout was used, not clock precision.
			if got < tc.want-time.Second || got > tc.want+time.Second {
				t.Fatalf("rollback deadline %v does not track the commit deadline %v", got, tc.want)
			}
			if got == 5*time.Second && tc.want != 5*time.Second {
				t.Fatal("rollback reverted to the hardcoded 5s deadline")
			}
		})
	}
}

// PAT-1512: migration 0109 recognises the nested tenant-purge context by
// pg_trigger_depth() = 2. That is true only while nothing else interposes a
// trigger between the tenants BEFORE DELETE and the assessment_artifact_audit
// UPDATE. If a future migration changes that depth, the guard either blocks a
// legitimate purge or admits a mutation it should refuse, and both are silent.
// The migration's own verification block checks trigger type bits, not depth
// isolation, so pin the assumption explicitly here.
func TestAssessmentAuditDepthAssumptionIsPinned(t *testing.T) {
	forward, err := os.ReadFile("../../migrations/0109_assessment_artifact_purge_anonymisation.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(forward)
	if !strings.Contains(text, "pg_trigger_depth() = 2") {
		t.Fatal("0109 no longer keys the purge exemption on pg_trigger_depth() = 2; if the mechanism changed to an explicit session marker, retire this test with it")
	}
	// The depth of 2 counts exactly one interposing trigger: the tenants
	// BEFORE DELETE anonymiser declared in 0101. 0109 only references it. A
	// second BEFORE DELETE trigger on tenants anywhere in the migration set
	// would change that depth, so assert the whole set still declares one.
	//
	// Limit worth knowing: this covers static declarations in the migration
	// files only. A trigger created at runtime, or one added directly to the
	// database outside migrations, would defeat it. That is an accepted gap --
	// migrations are the only sanctioned way schema changes reach production
	// here -- but it means this is a regression guard, not a proof.
	migrations, err := filepath.Glob("../../migrations/*.sql")
	if err != nil {
		t.Fatal(err)
	}
	declaring := []string{}
	for _, path := range migrations {
		if strings.Contains(path, "_rollback") {
			continue
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "BEFORE DELETE ON tenants") {
			declaring = append(declaring, filepath.Base(path))
		}
	}
	if len(declaring) != 1 {
		t.Fatalf("expected exactly 1 migration declaring a BEFORE DELETE trigger on tenants, found %d (%v); pg_trigger_depth() = 2 in 0109 assumes a single interposing trigger", len(declaring), declaring)
	}
}

// PAT-2410: generated report files live at <root>/<tenantID>/<recordID>/ and
// are quarantined with the same descriptor-relative discipline as assessment
// artefacts.

const purgeOtherTenant = "99999999-2222-4333-8444-555555555555"

func makeReportTree(t *testing.T, root, tenantID string) string {
	t.Helper()
	recDir := filepath.Join(root, tenantID, "aaaaaaaa-2222-4333-8444-555555555555")
	if err := os.MkdirAll(recDir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"report.pdf", "report.csv"} {
		if err := os.WriteFile(filepath.Join(recDir, name), []byte("report bytes "+name), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(root, tenantID)
}

func TestQuarantineReportFilesRemovesOnlyTheTenantDirectory(t *testing.T) {
	root := purgeTempRoot(t)
	tenantDir := makeReportTree(t, root, purgeTestTenant)
	otherReports := makeReportTree(t, root, purgeOtherTenant)
	assessmentDir := filepath.Join(root, "assessments", purgeOtherTenant)
	if err := os.MkdirAll(assessmentDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(assessmentDir, "a.pdf"), []byte("keep"), 0640); err != nil {
		t.Fatal(err)
	}

	q, err := quarantineReportFiles(root, purgeTestTenant)
	if err != nil || q == nil {
		t.Fatalf("quarantine: q=%v err=%v", q, err)
	}
	if _, err := os.Lstat(tenantDir); !os.IsNotExist(err) {
		t.Fatalf("tenant report directory still served after quarantine: %v", err)
	}
	residue := filepath.Join(root, q.residue())
	if err := q.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(residue); !os.IsNotExist(err) {
		t.Fatalf("report residue remains: %v", err)
	}
	if _, err := os.Lstat(tenantDir); !os.IsNotExist(err) {
		t.Fatalf("tenant report directory remains: %v", err)
	}
	for _, p := range []string{
		filepath.Join(otherReports, "aaaaaaaa-2222-4333-8444-555555555555", "report.pdf"),
		filepath.Join(otherReports, "aaaaaaaa-2222-4333-8444-555555555555", "report.csv"),
		filepath.Join(assessmentDir, "a.pdf"),
	} {
		if _, err := os.ReadFile(p); err != nil {
			t.Fatalf("unrelated file touched: %v", err)
		}
	}
}

func TestQuarantineReportFilesAbsentDirectoryIsNotAnError(t *testing.T) {
	root := purgeTempRoot(t)
	q, err := quarantineReportFiles(root, purgeTestTenant)
	if err != nil || q != nil {
		t.Fatalf("absent report directory: q=%v err=%v", q, err)
	}
	if err := q.Cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestQuarantineReportFilesRestoreAfterDatabaseFailure(t *testing.T) {
	root := purgeTempRoot(t)
	tenantDir := makeReportTree(t, root, purgeTestTenant)
	q, err := quarantineReportFiles(root, purgeTestTenant)
	if err != nil || q == nil {
		t.Fatalf("quarantine: q=%v err=%v", q, err)
	}
	if err := q.Restore(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"report.pdf", "report.csv"} {
		got, err := os.ReadFile(filepath.Join(tenantDir, "aaaaaaaa-2222-4333-8444-555555555555", name))
		if err != nil || string(got) != "report bytes "+name {
			t.Fatalf("%s not restored: %q %v", name, got, err)
		}
	}
	if q.residue() != "" {
		t.Fatalf("restore still reports residue: %q", q.residue())
	}
}

func TestQuarantineReportFilesRejectsEverythingButACanonicalUUID(t *testing.T) {
	root := purgeTempRoot(t)
	assessmentDir := filepath.Join(root, "assessments", purgeTestTenant)
	if err := os.MkdirAll(assessmentDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(assessmentDir, "a.pdf"), []byte("keep"), 0640); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{
		"", ".", "..", "../x", "assessments", "assessments/" + purgeTestTenant,
		assessmentQuarantineDir, "/", purgeTestTenant + "/..", purgeTestTenant + "/x",
		strings.ToUpper("g") + purgeTestTenant[1:],
	} {
		q, err := quarantineReportFiles(root, id)
		if err == nil || q != nil {
			t.Errorf("tenant id %q was accepted: q=%v err=%v", id, q, err)
		}
	}
	if _, err := os.ReadFile(filepath.Join(assessmentDir, "a.pdf")); err != nil {
		t.Fatalf("assessments content touched: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "assessments")); err != nil {
		t.Fatalf("assessments directory touched: %v", err)
	}
}
