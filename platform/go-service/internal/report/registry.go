package report

// SubjectScope identifies the object a report is generated for.
type SubjectScope string

const (
	SubjectTenant = SubjectScope("tenant")
	SubjectDevice = SubjectScope("device")
)

// ReportDefinition is the immutable product registry entry for one report.
// AdminPDFPath is a path template on the internal API. Customer-facing
// catalogue responses deliberately omit it because the portal generates
// reports through its authenticated tenant-scoped endpoint instead.
//
// AdminOnly (PAT-2406) marks a report whose content only a tenant admin may
// obtain through the portal API: generating it, downloading a stored copy,
// seeing it in the history or being offered it in the catalogue. It is the
// one place that rule is recorded; the portal handlers read it from here.
type ReportDefinition struct {
	Type             string       `json:"type"`
	Label            string       `json:"label"`
	Description      string       `json:"description"`
	DefaultFrequency string       `json:"default_frequency"`
	CustomerFacing   bool         `json:"customer_facing"`
	Subject          SubjectScope `json:"subject_scope"`
	AdminPDFPath     string       `json:"admin_pdf_path"`
	AdminOnly        bool         `json:"admin_only"`
}

// PortalReportDefinition is the customer-safe subset of ReportDefinition.
// Entitlement filtering belongs after this product-level customer-facing
// filter. No current tenant tier limits report availability.
type PortalReportDefinition struct {
	Type             string       `json:"type"`
	Label            string       `json:"label"`
	Description      string       `json:"description"`
	DefaultFrequency string       `json:"default_frequency"`
	Subject          SubjectScope `json:"subject_scope"`
	// AdminOnly is present (true) only on a report restricted to tenant
	// admins, and such an entry is only ever sent to an admin (PAT-2406).
	AdminOnly bool `json:"admin_only,omitempty"`
}

// reportRegistry is deliberately unexported. Callers receive value copies so
// one consumer cannot mutate catalogue metadata observed by another.
var reportRegistry = [...]ReportDefinition{
	{Type: "executive-summary", Label: "Executive Estate Summary", Description: "Device counts, compliance, patch posture and the controls needing most attention.", DefaultFrequency: "monthly", CustomerFacing: true, Subject: SubjectTenant, AdminPDFPath: "/admin/reports/executive-summary/{tenantID}.pdf"},
	{Type: "cis-compliance", Label: "CIS Compliance Report", Description: "Compliance results by benchmark section and control, including the devices needing most attention.", DefaultFrequency: "monthly", CustomerFacing: true, Subject: SubjectTenant, AdminPDFPath: "/admin/reports/cis-compliance/{tenantID}.pdf"},
	{Type: "cve-report", Label: "CVE / Vulnerability Exposure", Description: "Open vulnerabilities by severity, with the affected software and available evidence.", DefaultFrequency: "weekly", CustomerFacing: true, Subject: SubjectTenant, AdminPDFPath: "/admin/reports/cve/{tenantID}.pdf"},
	{Type: "patch-status", Label: "Patch & Update Status", Description: "Operating system and application updates reported as pending across the estate.", DefaultFrequency: "weekly", CustomerFacing: true, Subject: SubjectTenant, AdminPDFPath: "/admin/reports/patch-status/{tenantID}.pdf"},
	{Type: "stale-endpoints", Label: "Stale / Inactive Endpoints", Description: "Devices that have not reported within the configured freshness threshold.", DefaultFrequency: "weekly", CustomerFacing: true, Subject: SubjectTenant, AdminPDFPath: "/admin/reports/stale-endpoints/{tenantID}.pdf"},
	{Type: "cert-expiry", Label: "Certificate Expiry", Description: "Device certificates that are expired or approaching expiry.", DefaultFrequency: "monthly", CustomerFacing: true, Subject: SubjectTenant, AdminPDFPath: "/admin/reports/cert-expiry/{tenantID}.pdf"},
	{Type: "software-inventory", Label: "Software Inventory & Metering", Description: "Installed software across the estate, including available usage evidence.", DefaultFrequency: "monthly", CustomerFacing: false, Subject: SubjectTenant, AdminPDFPath: "/admin/reports/software-inventory/{tenantID}.pdf"},
	{Type: "app-policy-drift", Label: "App Policy Drift / Governance", Description: "Mandatory software reported missing and unapproved software reported present.", DefaultFrequency: "monthly", CustomerFacing: false, Subject: SubjectTenant, AdminPDFPath: "/admin/reports/app-policy-drift/{tenantID}.pdf"},
	{Type: "browser-extensions", Label: "Browser Extension Risk", Description: "Browser extensions with elevated permissions or broad access across the estate.", DefaultFrequency: "monthly", CustomerFacing: false, Subject: SubjectTenant, AdminPDFPath: "/admin/reports/browser-extensions/{tenantID}.pdf"},
	{Type: "edr-coverage", Label: "EDR / Security-Tooling Coverage", Description: "Devices reporting recognised endpoint detection and response tooling, including coverage gaps.", DefaultFrequency: "monthly", CustomerFacing: true, Subject: SubjectTenant, AdminPDFPath: "/admin/reports/edr-coverage/{tenantID}.pdf"},
	{Type: "device-health", Label: "Device Health / Hardware", Description: "Battery, storage and disk health signals reported across the estate.", DefaultFrequency: "monthly", CustomerFacing: false, Subject: SubjectTenant, AdminPDFPath: "/admin/reports/device-health/{tenantID}.pdf"},
	{Type: "encryption-posture", Label: "Encryption & Disk Posture", Description: "FileVault and BitLocker state reported by each device.", DefaultFrequency: "monthly", CustomerFacing: true, Subject: SubjectTenant, AdminPDFPath: "/admin/reports/encryption-posture/{tenantID}.pdf"},
	// PAT-2406: this report prints the standing local-administrator roster
	// (account names, personal data), so it follows the same admin-only rule
	// as GET /v1/portal/local-admins (PAT-2215).
	{Type: "local-admin", Label: "Local Admin / Privileged Access", Description: "Reported local administrator counts and privileged access exposure by device.", DefaultFrequency: "weekly", CustomerFacing: true, Subject: SubjectTenant, AdminPDFPath: "/admin/reports/local-admin/{tenantID}.pdf", AdminOnly: true},
	// PAT-2009 software governance reports. Data comes from internal/softwaregov,
	// the same code as the portal JSON and CSV endpoints.
	{Type: "new-software", Label: "New Software", Description: "Software first reported in the estate since the last approval review, with when and where it was first seen.", DefaultFrequency: "weekly", CustomerFacing: true, Subject: SubjectTenant, AdminPDFPath: "/admin/reports/new-software/{tenantID}.pdf"},
	{Type: "software-drift", Label: "Unapproved & Unreviewed Software", Description: "Installed software that is Unapproved or not yet reviewed, where Unapproved software is present, the weekly trend and the devices carrying the most.", DefaultFrequency: "weekly", CustomerFacing: true, Subject: SubjectTenant, AdminPDFPath: "/admin/reports/software-drift/{tenantID}.pdf"},
	{Type: "approved-software", Label: "Approved Software List", Description: "Every approved product, with who approved it and when.", DefaultFrequency: "monthly", CustomerFacing: true, Subject: SubjectTenant, AdminPDFPath: "/admin/reports/approved-software/{tenantID}.pdf"},
	{Type: "ai-tooling-evidence", Label: "AI Tooling Evidence", Description: "Current AI tooling identities, collection coverage, approval state and exact vulnerability assessment evidence by device.", DefaultFrequency: "monthly", CustomerFacing: true, Subject: SubjectTenant, AdminPDFPath: "/admin/reports/ai-tooling-evidence/{tenantID}.pdf"},
	// PAT-2258: answers to the endpoint questions on a cyber insurance
	// renewal form, from the existing read models (insurance_evidence.go).
	{Type: "insurance-evidence", Label: "Cyber Insurance Evidence Pack", Description: "Answers to the endpoint questions on a typical cyber insurance renewal form, each from Patched's evidence with its source and date, plus the questions Patched cannot evidence.", DefaultFrequency: "monthly", CustomerFacing: true, Subject: SubjectTenant, AdminPDFPath: "/admin/reports/insurance-evidence/{tenantID}.pdf"},
	{Type: "device-compliance", Label: "Device Compliance Report", Description: "Detailed compliance evidence for one device.", DefaultFrequency: "ad_hoc", CustomerFacing: false, Subject: SubjectDevice, AdminPDFPath: "/admin/reports/{deviceID}/compliance.pdf"},
}

// ReportCatalogue returns all registered report definitions as a fresh slice.
func ReportCatalogue() []ReportDefinition {
	entries := make([]ReportDefinition, len(reportRegistry))
	copy(entries, reportRegistry[:])
	return entries
}

// LookupReportDefinition returns a value copy of one registered definition.
func LookupReportDefinition(reportType string) (ReportDefinition, bool) {
	for _, entry := range reportRegistry {
		if entry.Type == reportType {
			return entry, true
		}
	}
	return ReportDefinition{}, false
}

// AdminOnlyReportTypes returns the type keys of every admin-only report, as a
// fresh slice (PAT-2406).
func AdminOnlyReportTypes() []string {
	types := []string{}
	for _, entry := range reportRegistry {
		if entry.AdminOnly {
			types = append(types, entry.Type)
		}
	}
	return types
}

// PortalReportCatalogue returns the product-level customer-facing set. A
// future entitlement filter can consume this result using tenant capabilities;
// the registry itself must remain independent of commercial tiers. Admin-only
// entries are included and flagged; the portal handler removes them for a
// caller who is not an admin.
func PortalReportCatalogue() []PortalReportDefinition {
	entries := make([]PortalReportDefinition, 0, len(reportRegistry))
	for _, entry := range reportRegistry {
		if !entry.CustomerFacing || entry.Subject != SubjectTenant {
			continue
		}
		entries = append(entries, PortalReportDefinition{
			Type:             entry.Type,
			Label:            entry.Label,
			Description:      entry.Description,
			DefaultFrequency: entry.DefaultFrequency,
			Subject:          entry.Subject,
			AdminOnly:        entry.AdminOnly,
		})
	}
	return entries
}
