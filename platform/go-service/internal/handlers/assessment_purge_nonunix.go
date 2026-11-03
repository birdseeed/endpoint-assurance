//go:build !unix

package handlers

import "errors"

// Assessment purge is deployed on Linux. Non-Unix builds fail closed rather
// than substituting path-based filesystem operations for the descriptor-safe
// implementation in assessment_purge.go.
type assessmentQuarantine struct{}

const assessmentQuarantineDir = ".assessment-purge-quarantine"

var assessmentQuarantineFsync = func(int) error { return nil }

func quarantineAssessmentArtifacts(string, string, bool) (*assessmentQuarantine, error) {
	return nil, errors.New("assessment artifact quarantine requires a Unix platform")
}

func quarantineReportFiles(string, string) (*assessmentQuarantine, error) {
	return nil, errors.New("report file quarantine requires a Unix platform")
}

func validateAssessmentStorageRoot(string, bool) error {
	return errors.New("assessment artifact quarantine requires a Unix platform")
}

func (*assessmentQuarantine) Restore() error  { return nil }
func (*assessmentQuarantine) Cleanup() error  { return nil }
func (*assessmentQuarantine) residue() string { return "" }
