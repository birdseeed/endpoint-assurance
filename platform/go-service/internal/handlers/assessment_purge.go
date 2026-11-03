//go:build unix

package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const assessmentQuarantineDir = ".assessment-purge-quarantine"
const assessmentCleanupMaxDepth = 128

// Test seam for the final quarantine-directory durability barrier. Production
// always uses unix.Fsync; tests replace it only to exercise the state after a
// successful unlink followed by an fsync failure.
var assessmentQuarantineFsync = unix.Fsync

var assessmentQuarantineMkdirat = unix.Mkdirat
var assessmentStorageRootFsync = unix.Fsync

type fileIdentity struct {
	dev uint64
	ino uint64
}

type assessmentQuarantine struct {
	root     string
	tenantID string
	// parent is the directory under the storage root that held the tenant
	// directory: "assessments" for assessment artefacts, "" for the root
	// itself (generated report files, PAT-2410).
	parent string
	name   string
	rootID fileIdentity
	dirID  fileIdentity
}

func statIdentity(st *unix.Stat_t) fileIdentity {
	return fileIdentity{dev: uint64(st.Dev), ino: uint64(st.Ino)}
}

func openDirectoryAt(parentFD int, name string) (int, unix.Stat_t, error) {
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, unix.Stat_t{}, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, errors.New("component is not a directory")
	}
	return fd, st, nil
}

func openStorageRoot(root string, expected *fileIdentity) (int, fileIdentity, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return -1, fileIdentity{}, err
	}
	// O_NOFOLLOW on the final path does not protect intermediate components.
	// Walk from / descriptor-by-descriptor so no root component is followed.
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fileIdentity{}, fmt.Errorf("open report storage root: %w", err)
	}
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Clean(abs), "/"), "/") {
		if component == "" {
			continue
		}
		nextFD, _, openErr := openDirectoryAt(fd, component)
		_ = unix.Close(fd)
		if openErr != nil {
			return -1, fileIdentity{}, fmt.Errorf("open report storage root component %q: %w", component, openErr)
		}
		fd = nextFD
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return -1, fileIdentity{}, err
	}
	id := statIdentity(&st)
	if expected != nil && id != *expected {
		_ = unix.Close(fd)
		return -1, fileIdentity{}, errors.New("report storage root identity changed")
	}
	return fd, id, nil
}

func openOrCreateQuarantine(rootFD int) (int, error) {
	var rootStat unix.Stat_t
	if err := unix.Fstat(rootFD, &rootStat); err != nil {
		return -1, err
	}
	fd, quarantineStat, err := openDirectoryAt(rootFD, assessmentQuarantineDir)
	if err == nil {
		if err := validateAssessmentQuarantineBoundary(rootStat, quarantineStat); err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
		return fd, nil
	}
	if !errors.Is(err, unix.ENOENT) {
		return -1, fmt.Errorf("unsafe assessment quarantine component: %w", err)
	}
	if err := assessmentQuarantineMkdirat(rootFD, assessmentQuarantineDir, 0700); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return -1, errors.New("assessment quarantine appeared concurrently; refusing to adopt raced boundary")
		}
		return -1, fmt.Errorf("create assessment quarantine: %w", err)
	}
	fd, quarantineStat, err = openDirectoryAt(rootFD, assessmentQuarantineDir)
	if err != nil {
		return -1, fmt.Errorf("open assessment quarantine: %w", err)
	}
	if err := validateAssessmentQuarantineBoundary(rootStat, quarantineStat); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	// Persist the new trust boundary before moving customer bytes into it.
	// A failure leaves only an empty, validated directory and aborts the purge.
	if err := assessmentStorageRootFsync(rootFD); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("sync new assessment quarantine boundary: %w", err)
	}
	return fd, nil
}

func validateAssessmentQuarantineBoundary(rootStat, quarantineStat unix.Stat_t) error {
	if quarantineStat.Uid != rootStat.Uid || quarantineStat.Mode&0022 != 0 || quarantineStat.Mode&0700 != 0700 {
		return errors.New("assessment quarantine has unsafe ownership or mode")
	}
	if quarantineStat.Dev != rootStat.Dev {
		return fmt.Errorf("assessment quarantine is on a different device: %w", unix.EXDEV)
	}
	return nil
}

func randomQuarantineName(tenantID string) (string, error) {
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return tenantID + "-" + hex.EncodeToString(nonce[:]), nil
}

func restoreUnexpectedRename(assessmentsFD, quarantineFD int, tenantID, name string, expected fileIdentity) (bool, error) {
	var quarantineStat unix.Stat_t
	if err := unix.Fstatat(quarantineFD, name, &quarantineStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return true, err
	}
	if statIdentity(&quarantineStat) != expected {
		return true, errors.New("refusing to restore unverified quarantine identity")
	}
	var st unix.Stat_t
	err := unix.Fstatat(assessmentsFD, tenantID, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		return true, errors.New("tenant assessment path was replaced during quarantine")
	}
	if !errors.Is(err, unix.ENOENT) {
		return true, err
	}
	if err := unix.Renameat(quarantineFD, name, assessmentsFD, tenantID); err != nil {
		return true, err
	}
	if err := unix.Fstatat(assessmentsFD, tenantID, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil || statIdentity(&st) != expected {
		moveAwayErr := unix.Renameat(assessmentsFD, tenantID, quarantineFD, name)
		return moveAwayErr == nil, errors.Join(errors.New("restored assessment identity could not be verified"), err, moveAwayErr)
	}
	return false, errors.Join(unix.Fsync(assessmentsFD), unix.Fsync(quarantineFD))
}

func quarantineAssessmentArtifacts(root, tenantID string, artifactsExpected bool) (*assessmentQuarantine, error) {
	return quarantineAssessmentArtifactsWithHook(root, tenantID, artifactsExpected, nil)
}

func validateAssessmentStorageRoot(root string, artifactsExpected bool) error {
	rootFD, _, err := openStorageRoot(root, nil)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	var rootStat unix.Stat_t
	if err := unix.Fstat(rootFD, &rootStat); err != nil {
		return err
	}
	assessmentsFD, assessmentsStat, err := openDirectoryAt(rootFD, "assessments")
	if errors.Is(err, unix.ENOENT) {
		if artifactsExpected {
			return errors.New("assessment artifacts exist in database but assessments hierarchy is absent")
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("assessments directory is unsafe: %w", err)
	}
	defer unix.Close(assessmentsFD)
	if err := validateAssessmentStorageComponent("assessments", rootStat, assessmentsStat); err != nil {
		return err
	}
	quarantineFD, quarantineStat, err := openDirectoryAt(rootFD, assessmentQuarantineDir)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("quarantine directory is unsafe: %w", err)
	}
	defer unix.Close(quarantineFD)
	if err := validateAssessmentStorageComponent("quarantine", rootStat, quarantineStat); err != nil {
		return err
	}
	if assessmentsStat.Dev != quarantineStat.Dev {
		return fmt.Errorf("assessment quarantine rename would cross devices: %w", unix.EXDEV)
	}
	return nil
}

func validateAssessmentStorageComponent(label string, rootStat, component unix.Stat_t) error {
	if component.Uid != rootStat.Uid || component.Mode&0022 != 0 || component.Mode&0700 != 0700 {
		return fmt.Errorf("%s directory has incompatible ownership or permissions", label)
	}
	if component.Dev != rootStat.Dev {
		return fmt.Errorf("%s directory is on a different device: %w", label, unix.EXDEV)
	}
	return nil
}

// The hook exists only to deterministically exercise the open-to-rename race
// in tests. Production always calls quarantineAssessmentArtifacts.
func quarantineAssessmentArtifactsWithHook(root, tenantID string, artifactsExpected bool, beforeRename func()) (*assessmentQuarantine, error) {
	return quarantineTenantDirWithHook(root, "assessments", tenantID, artifactsExpected, beforeRename)
}

// quarantineReportFiles moves the tenant's generated-report directory
// (<root>/<tenantID>, holding <recordID>/report.pdf and report.csv) into the
// same root-confined quarantine as assessment artefacts (PAT-2410). The
// tenant ID must be a canonical UUID, which can never equal "assessments" or
// the quarantine directory name, so this cannot touch either. An absent
// directory is not an error: not every tenant has generated a report.
func quarantineReportFiles(root, tenantID string) (*assessmentQuarantine, error) {
	return quarantineTenantDirWithHook(root, "", tenantID, false, nil)
}

// quarantineTenantDirWithHook quarantines <root>/<parent>/<tenantID>, or
// <root>/<tenantID> when parent is "".
func quarantineTenantDirWithHook(root, parent, tenantID string, artifactsExpected bool, beforeRename func()) (*assessmentQuarantine, error) {
	if !looksLikeUUID(tenantID) {
		return nil, errors.New("invalid tenant assessment directory name")
	}
	rootFD, rootID, err := openStorageRoot(root, nil)
	if err != nil {
		return nil, err
	}
	defer unix.Close(rootFD)

	assessmentsFD := rootFD
	if parent != "" {
		var parentFD int
		parentFD, _, err = openDirectoryAt(rootFD, parent)
		if errors.Is(err, unix.ENOENT) {
			if artifactsExpected {
				return nil, errors.New("assessment artifacts exist in database but assessments hierarchy is absent")
			}
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("unsafe assessments component: %w", err)
		}
		defer unix.Close(parentFD)
		assessmentsFD = parentFD
	}

	sourceFD, sourceStat, err := openDirectoryAt(assessmentsFD, tenantID)
	if errors.Is(err, unix.ENOENT) {
		if artifactsExpected {
			return nil, errors.New("assessment artifacts exist in database but tenant directory is absent")
		}
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("unsafe tenant assessment directory: %w", err)
	}
	defer unix.Close(sourceFD)

	quarantineFD, err := openOrCreateQuarantine(rootFD)
	if err != nil {
		return nil, err
	}
	defer unix.Close(quarantineFD)

	name, err := randomQuarantineName(tenantID)
	if err != nil {
		return nil, err
	}
	if beforeRename != nil {
		beforeRename()
	}
	if err := unix.Renameat(assessmentsFD, tenantID, quarantineFD, name); err != nil {
		return nil, fmt.Errorf("quarantine tenant assessments: %w", err)
	}
	q := &assessmentQuarantine{
		root: root, tenantID: tenantID, parent: parent, name: name, rootID: rootID,
		dirID: statIdentity(&sourceStat),
	}

	movedFD, movedStat, err := openDirectoryAt(quarantineFD, name)
	if err != nil {
		inQuarantine, restoreErr := restoreUnexpectedRename(assessmentsFD, quarantineFD, tenantID, name, q.dirID)
		if !inQuarantine {
			q.name = ""
		}
		if restoreErr == nil {
			return nil, &postRenameQuarantineError{err: fmt.Errorf("quarantined path verification failed and bytes were restored: %w", err), restored: true}
		}
		return q, errors.Join(fmt.Errorf("quarantined path is not a real directory: %w", err), restoreErr)
	}
	_ = unix.Close(movedFD)
	if statIdentity(&movedStat) != statIdentity(&sourceStat) {
		// The name resolved to a different inode between verification and
		// rename. Never publish that unverified replacement back under the
		// served assessments path: leave it quarantined for investigation.
		return q, fmt.Errorf("tenant assessment directory identity changed before quarantine; unverified residue retained at %s/%s", assessmentQuarantineDir, name)
	}
	if err := errors.Join(unix.Fsync(assessmentsFD), unix.Fsync(quarantineFD)); err != nil {
		restoreErr := q.Restore()
		if restoreErr == nil {
			return nil, &postRenameQuarantineError{err: fmt.Errorf("sync assessment quarantine rename failed and bytes were restored: %w", err), restored: true}
		}
		return q, errors.Join(fmt.Errorf("sync assessment quarantine rename: %w", err), restoreErr)
	}

	return q, nil
}

func (q *assessmentQuarantine) residue() string {
	if q == nil || q.name == "" {
		return ""
	}
	return filepath.Join(assessmentQuarantineDir, q.name)
}

func (q *assessmentQuarantine) openVerified(openAssessments bool) (rootFD, assessmentsFD, quarantineFD, dirFD int, err error) {
	rootFD, assessmentsFD, quarantineFD, dirFD = -1, -1, -1, -1
	rootFD, _, err = openStorageRoot(q.root, &q.rootID)
	if err != nil {
		return -1, -1, -1, -1, err
	}
	closeOnError := func() {
		for _, fd := range []int{dirFD, quarantineFD, assessmentsFD, rootFD} {
			if fd >= 0 {
				_ = unix.Close(fd)
			}
		}
	}
	if openAssessments && q.parent == "" {
		// The tenant directory's parent is the root itself; hold a separate
		// descriptor so closeFDs semantics match the assessments case.
		assessmentsFD, err = unix.Dup(rootFD)
		if err != nil {
			closeOnError()
			return -1, -1, -1, -1, err
		}
	} else if openAssessments {
		var assessmentsStat unix.Stat_t
		assessmentsFD, assessmentsStat, err = openDirectoryAt(rootFD, q.parent)
		if err != nil {
			closeOnError()
			return -1, -1, -1, -1, err
		}
		var rootStat unix.Stat_t
		if err := unix.Fstat(rootFD, &rootStat); err != nil {
			closeOnError()
			return -1, -1, -1, -1, err
		}
		if err := validateAssessmentStorageComponent(q.parent, rootStat, assessmentsStat); err != nil {
			closeOnError()
			return -1, -1, -1, -1, err
		}
	}
	quarantineFD, quarantineStat, err := openDirectoryAt(rootFD, assessmentQuarantineDir)
	if err != nil {
		closeOnError()
		return -1, -1, -1, -1, err
	}
	var rootStat unix.Stat_t
	if err := unix.Fstat(rootFD, &rootStat); err != nil {
		closeOnError()
		return -1, -1, -1, -1, err
	}
	if err := validateAssessmentQuarantineBoundary(rootStat, quarantineStat); err != nil {
		closeOnError()
		return -1, -1, -1, -1, err
	}
	dirFD, st, err := openDirectoryAt(quarantineFD, q.name)
	if err != nil || statIdentity(&st) != q.dirID {
		closeOnError()
		if err == nil {
			err = errors.New("quarantine residue identity changed")
		}
		return -1, -1, -1, -1, err
	}
	return rootFD, assessmentsFD, quarantineFD, dirFD, nil
}

func closeFDs(fds ...int) {
	for _, fd := range fds {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}
}

func (q *assessmentQuarantine) Restore() error {
	if q == nil {
		return nil
	}
	rootFD, assessmentsFD, quarantineFD, dirFD, err := q.openVerified(true)
	if err != nil {
		return err
	}
	defer closeFDs(dirFD, quarantineFD, assessmentsFD, rootFD)

	var st unix.Stat_t
	err = unix.Fstatat(assessmentsFD, q.tenantID, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		return errors.New("refusing to overwrite replacement tenant assessment path")
	}
	if !errors.Is(err, unix.ENOENT) {
		return err
	}
	quarantineName := q.name
	if err := unix.Renameat(quarantineFD, quarantineName, assessmentsFD, q.tenantID); err != nil {
		return err
	}
	// The residue path ceased to exist at rename. Clear it before any later
	// verification or fsync can fail so callers never report a ghost residue.
	q.name = ""
	restoredFD, restoredStat, err := openDirectoryAt(assessmentsFD, q.tenantID)
	if err != nil {
		if moveErr := unix.Renameat(assessmentsFD, q.tenantID, quarantineFD, quarantineName); moveErr == nil {
			q.name = quarantineName
			return errors.Join(errors.New("restored path verification failed; content returned to quarantine"), err)
		}
		return errors.Join(errors.New("restored path verification failed; content remains served but unverified"), err)
	}
	_ = unix.Close(restoredFD)
	if statIdentity(&restoredStat) != q.dirID {
		// The quarantine name was replaced after verification. Move the
		// unexpected directory back outside the served tree before refusing.
		if moveErr := unix.Renameat(assessmentsFD, q.tenantID, quarantineFD, quarantineName); moveErr == nil {
			q.name = quarantineName
			return errors.New("restored tenant assessment identity mismatch; content returned to quarantine")
		}
		return errors.New("restored tenant assessment identity mismatch; content remains served but unverified")
	}
	return errors.Join(unix.Fsync(assessmentsFD), unix.Fsync(quarantineFD))
}

func removeTreeAt(parentFD int, name string, expected fileIdentity, depth int) error {
	if depth > assessmentCleanupMaxDepth {
		return fmt.Errorf("quarantine tree exceeds maximum cleanup depth %d", assessmentCleanupMaxDepth)
	}
	dirFD, st, err := openDirectoryAt(parentFD, name)
	if err != nil {
		return err
	}
	defer unix.Close(dirFD)
	if statIdentity(&st) != expected {
		return errors.New("quarantine residue identity changed before cleanup")
	}

	dupFD, err := unix.Dup(dirFD)
	if err != nil {
		return err
	}
	dirFile := os.NewFile(uintptr(dupFD), name)
	names, readErr := dirFile.Readdirnames(-1)
	closeErr := dirFile.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	for _, child := range names {
		var childStat unix.Stat_t
		if err := unix.Fstatat(dirFD, child, &childStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if childStat.Mode&unix.S_IFMT == unix.S_IFDIR {
			if err := removeTreeAt(dirFD, child, statIdentity(&childStat), depth+1); err != nil {
				return err
			}
			continue
		}
		if err := unix.Unlinkat(dirFD, child, 0); err != nil {
			return err
		}
	}
	var finalStat unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &finalStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if statIdentity(&finalStat) != expected {
		return errors.New("directory identity changed during cleanup")
	}
	return unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
}

func (q *assessmentQuarantine) Cleanup() error {
	if q == nil {
		return nil
	}
	rootFD, _, quarantineFD, dirFD, err := q.openVerified(false)
	if err != nil {
		return err
	}
	closeFDs(dirFD)
	defer closeFDs(quarantineFD, rootFD)
	if err := removeTreeAt(quarantineFD, q.name, q.dirID, 0); err != nil {
		return err
	}
	// The residue path ceased to exist when removeTreeAt succeeded. Clear it
	// before the durability barrier so an fsync failure cannot make callers
	// report a path that has already been deleted.
	q.name = ""
	return assessmentQuarantineFsync(quarantineFD)
}
