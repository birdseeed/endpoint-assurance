package automations

// RegisteredJobs returns registry metadata only, without reading private run
// output. Callers must still filter Lifecycle before treating a job as active.
func RegisteredJobs() []JobSummary {
	return append([]JobSummary(nil), knownJobs...)
}
