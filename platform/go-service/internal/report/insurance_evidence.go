package report

// Cyber insurance evidence pack (PAT-2258): the read model behind
// GET /v1/portal/insurance-evidence and the insurance-evidence report.
//
// Every SME answers a cyber insurance renewal questionnaire each year, and
// its endpoint questions are nearly the same from one insurer to the next.
// This answers those questions from evidence Patched already holds, each
// with its source, the time it was produced and how many devices it could
// not speak for. It never states a verdict, and nothing here says or
// implies that the organisation qualifies for cover or for better terms.
//
// Rules this file keeps:
//
//   - One calculation. Every answer is read off an existing read model
//     (FetchPortalCEReadiness, FetchEDRCoverageReport,
//     FetchEncryptionPostureReport, FetchLocalAdminReport, lifecycle.Build,
//     remoteaccess.Build) using that model's own per-device classification.
//     Nothing here re-derives a state.
//   - One estate. The in-scope devices are the CE readiness devices: not
//     retired, on an enabled platform. A device in a source model but
//     outside that set is not counted; a device in that set but missing
//     from a source model is unknown.
//   - Unknown is never compliant. A device that has not reported within
//     InsuranceReportingWindow, or has no evidence for a question, is
//     counted as unknown for that question and never towards a positive
//     figure. Percentages are always over every in-scope device.
//   - Nothing is omitted. The questions Patched holds no evidence for are
//     always present, marked not_evidenced_by_patched.
//   - Failure isolation. Only the tenant lookup and the CE readiness read
//     can fail the pack. Any other source failing turns its question into
//     unknown with reason source_unavailable, never a partial figure.
//
// The question list lives in one place, insuranceQuestions, so its wording
// can be edited without touching the calculations.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/lifecycle"
	"patched.im/api/internal/remoteaccess"
	"patched.im/api/internal/softwaregov"
)

// InsuranceReportingWindow is how recently a device must have reported for
// its evidence to count: the same 14 days as softwaregov.StaleAfter and the
// CE readiness silent threshold, so "not reporting" means one thing across
// the portal.
const InsuranceReportingWindow = softwaregov.StaleAfter

// Answer statuses. They describe how much of the estate the evidence
// covers, never whether the answer is a good one.
const (
	InsuranceEvidenced    = "evidenced"
	InsurancePartial      = "partial"
	InsuranceUnknown      = "unknown"
	InsuranceNotEvidenced = "not_evidenced_by_patched"
)

// Question groups.
const (
	InsuranceGroupEvidenced    = "evidenced_by_patched"
	InsuranceGroupNotEvidenced = "not_evidenced_by_patched"
)

// Bounded reason codes.
const (
	InsuranceReasonSourceUnavailable = "source_unavailable"
	InsuranceReasonEstateTooLarge    = "estate_too_large"
	InsuranceReasonNoDevices         = "no_devices"
	InsuranceReasonCatalogueLimited  = "catalogue_limited"
	InsuranceReasonOutsideEvidence   = "outside_patched_evidence"
)

// InsuranceStatement is the pack's standing caveat, printed on every
// surface that shows the pack.
const InsuranceStatement = "This pack states what Patched's endpoint evidence showed when it was produced, " +
	"with the source and date of every answer. It is not an audit, a certification or a guarantee, " +
	"and it does not decide any question of cover. Devices Patched could not see, or that had not " +
	"reported recently, are shown as unknown and are never counted in your favour. Questions " +
	"Patched holds no evidence for are listed as not evidenced by Patched, for you to answer from " +
	"your own records."

// InsuranceSource names the portal view an answer is drawn from.
type InsuranceSource struct {
	Label string `json:"label"`
	Path  string `json:"path"`
}

// InsuranceValue is the structured answer. Value is the headline figure
// (Unit says what it counts), Percentage is Value over every in-scope
// device where a share makes sense, and Counts carries every figure the
// answer text quotes.
type InsuranceValue struct {
	Value      *int           `json:"value"`
	Unit       string         `json:"unit"`
	Percentage *float64       `json:"percentage"`
	Counts     map[string]int `json:"counts"`
}

// InsuranceAnswer is one question and its evidence-based answer.
type InsuranceAnswer struct {
	ID               string           `json:"id"`
	Group            string           `json:"group"`
	Title            string           `json:"title"`
	Question         string           `json:"question"`
	Status           string           `json:"status"`
	Reason           *string          `json:"reason"`
	Answer           InsuranceValue   `json:"answer"`
	UnknownDevices   *int             `json:"unknown_devices"`
	AsOf             *time.Time       `json:"as_of"`
	OldestEvidenceAt *time.Time       `json:"oldest_evidence_at"`
	Source           *InsuranceSource `json:"source"`
	Headline         string           `json:"headline"`
	AnswerText       string           `json:"answer_text"`
	Basis            string           `json:"basis"`
}

// InsuranceEvidence is the GET /v1/portal/insurance-evidence response.
type InsuranceEvidence struct {
	GeneratedAt         time.Time         `json:"generated_at"`
	Tenant              string            `json:"-"`
	Statement           string            `json:"statement"`
	ReportingWindowDays int               `json:"reporting_window_days"`
	DevicesInScope      int               `json:"devices_in_scope"`
	RetiredExcluded     int               `json:"retired_excluded"`
	Questions           []InsuranceAnswer `json:"questions"`
}

// insuranceQuestion is one entry of the question list. answer is nil for a
// question Patched holds no evidence for; outOfScope then says what the
// customer should answer it from.
type insuranceQuestion struct {
	ID         string
	Title      string
	Question   string
	Source     *InsuranceSource
	answer     func(*insuranceSources) InsuranceAnswer
	outOfScope string
}

// insuranceQuestions is THE question list, in the order the pack prints it.
// Wording is a neutral paraphrase of the endpoint questions common to cyber
// insurance renewal forms; it copies no insurer's text. Edit wording here;
// the answers are computed by the functions named in each entry.
var insuranceQuestions = []insuranceQuestion{
	{
		ID:       "edr_coverage",
		Title:    "EDR and anti-malware",
		Question: "Do all of your endpoints have endpoint detection and response (EDR) or anti-malware protection?",
		Source:   &InsuranceSource{Label: "Cyber Essentials readiness (EDR coverage)", Path: "/ce-readiness"},
		answer:   insuranceEDR,
	},
	{
		ID:       "disk_encryption",
		Title:    "Full-disk encryption",
		Question: "Are your laptops and other endpoints protected by full-disk encryption?",
		Source:   &InsuranceSource{Label: "Encryption and disk posture report", Path: "/reports"},
		answer:   insuranceEncryption,
	},
	{
		ID:       "patching_speed",
		Title:    "Security update speed",
		Question: "How quickly are critical and high severity security updates applied, and are any outstanding for more than 14 or 30 days?",
		Source:   &InsuranceSource{Label: "Cyber Essentials readiness", Path: "/ce-readiness"},
		answer:   insurancePatching,
	},
	{
		ID:       "unsupported_software",
		Title:    "Unsupported systems and software",
		Question: "Do any of your endpoints run an operating system or software that its vendor no longer supports?",
		Source:   &InsuranceSource{Label: "Unsupported software report", Path: "/reports/software/unsupported"},
		answer:   insuranceUnsupported,
	},
	{
		ID:       "local_admin_rights",
		Title:    "Local administrator rights",
		Question: "How many user accounts hold standing local administrator rights on your endpoints?",
		Source:   &InsuranceSource{Label: "Local admin and privileged access report", Path: "/reports"},
		answer:   insuranceLocalAdmin,
	},
	{
		ID:       "remote_access_tools",
		Title:    "Remote access tools",
		Question: "Which remote access tools are present on your endpoints, and has your organisation approved them?",
		Source:   &InsuranceSource{Label: "Remote access tools report", Path: "/reports/software/remote-access"},
		answer:   insuranceRemoteAccess,
	},
	{
		ID:       "asset_inventory",
		Title:    "Endpoint inventory",
		Question: "Do you keep an inventory of your endpoints, and how much of the estate reports into it?",
		Source:   &InsuranceSource{Label: "Devices", Path: "/devices"},
		answer:   insuranceAssetInventory,
	},
	{
		ID:         "mfa",
		Title:      "Multi-factor authentication",
		Question:   "Is multi-factor authentication enforced for email, remote access and privileged accounts?",
		outOfScope: "your identity provider or email platform's sign-in settings",
	},
	{
		ID:         "email_security",
		Title:      "Email security",
		Question:   "Is inbound email filtered for malicious attachments, links and spoofed senders?",
		outOfScope: "your email platform or email security provider",
	},
	{
		ID:         "backups",
		Title:      "Backups",
		Question:   "Do you keep regular, tested backups that are held offline or otherwise separated from your network?",
		outOfScope: "your backup provider's job and restore test records",
	},
	{
		ID:         "incident_response",
		Title:      "Incident response plan",
		Question:   "Do you have a documented incident response plan, and has it been tested?",
		outOfScope: "your own incident response plan and its test records",
	},
	{
		ID:         "security_training",
		Title:      "Security awareness training",
		Question:   "Do staff receive regular security awareness and phishing training?",
		outOfScope: "your training provider's completion records",
	},
}

// InsuranceQuestionIDs returns every question id in pack order.
func InsuranceQuestionIDs() []string {
	ids := make([]string, len(insuranceQuestions))
	for i, q := range insuranceQuestions {
		ids[i] = q.ID
	}
	return ids
}

// insuranceSources is everything the answers read. A nil source with a
// non-nil error means that read failed.
type insuranceSources struct {
	now   time.Time
	ce    PortalCEReadiness
	scope []CEDevice // in-scope devices, from ce

	edr    *EDRCoverageReport
	edrErr error
	enc    *EncryptionPostureReport
	encErr error
	admin  *LocalAdminReport
	admErr error
	life   *lifecycle.Report
	lifErr error
	remote *remoteaccess.Report
	remErr error
}

// FetchInsuranceEvidence builds the pack for tenantID. It returns
// ErrTenantNotFound for an unknown tenant and an error only when the tenant
// lookup or the CE readiness read fails.
func FetchInsuranceEvidence(ctx context.Context, pool *pgxpool.Pool, tenantID string) (InsuranceEvidence, error) {
	var tenant string
	if err := pool.QueryRow(ctx, `SELECT name FROM tenants WHERE id = $1::uuid`, tenantID).Scan(&tenant); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return InsuranceEvidence{}, ErrTenantNotFound
		}
		return InsuranceEvidence{}, fmt.Errorf("fetch tenant: %w", err)
	}
	ce, err := FetchPortalCEReadiness(ctx, pool, tenantID)
	if err != nil {
		return InsuranceEvidence{}, fmt.Errorf("insurance evidence: ce readiness: %w", err)
	}
	s := &insuranceSources{now: ce.GeneratedAt, ce: ce}

	warn := func(source string, err error) {
		slog.Warn("insurance evidence: source read failed", "tenant_id", tenantID, "source", source, "err", err)
	}
	if r, err := FetchEDRCoverageReport(ctx, pool, tenantID); err != nil {
		s.edrErr = err
		warn("edr_coverage", err)
	} else {
		s.edr = &r
	}
	if r, err := FetchEncryptionPostureReport(ctx, pool, tenantID); err != nil {
		s.encErr = err
		warn("encryption_posture", err)
	} else {
		s.enc = &r
	}
	if r, err := FetchLocalAdminReport(ctx, pool, tenantID); err != nil {
		s.admErr = err
		warn("local_admin", err)
	} else {
		s.admin = &r
	}
	if r, err := lifecycle.Build(ctx, pool, tenantID, s.now); err != nil {
		s.lifErr = err
		warn("unsupported_software", err)
	} else {
		s.life = &r
	}
	if r, err := remoteaccess.Build(ctx, pool, tenantID, s.now); err != nil {
		s.remErr = err
		warn("remote_access", err)
	} else {
		s.remote = &r
	}
	out := buildInsuranceEvidence(s)
	out.Tenant = tenant
	return out, nil
}

// buildInsuranceEvidence assembles the pack from already-read sources. It
// does no I/O, so every rule above is unit-testable without a database.
func buildInsuranceEvidence(s *insuranceSources) InsuranceEvidence {
	s.scope = s.ce.Devices
	out := InsuranceEvidence{
		GeneratedAt:         s.now,
		Statement:           InsuranceStatement,
		ReportingWindowDays: int(InsuranceReportingWindow / (24 * time.Hour)),
		DevicesInScope:      len(s.scope),
		RetiredExcluded:     s.ce.Estate.RetiredExcluded,
		Questions:           make([]InsuranceAnswer, 0, len(insuranceQuestions)),
	}
	for _, q := range insuranceQuestions {
		var a InsuranceAnswer
		if q.answer == nil {
			a = insuranceNotEvidenced(q)
		} else {
			a = q.answer(s)
			a.Group = InsuranceGroupEvidenced
			a.Source = q.Source
		}
		a.ID, a.Title, a.Question = q.ID, q.Title, q.Question
		if a.Answer.Counts == nil {
			a.Answer.Counts = map[string]int{}
		}
		out.Questions = append(out.Questions, a)
	}
	return out
}

func insuranceNotEvidenced(q insuranceQuestion) InsuranceAnswer {
	return InsuranceAnswer{
		Group:    InsuranceGroupNotEvidenced,
		Status:   InsuranceNotEvidenced,
		Reason:   ceReason(InsuranceReasonOutsideEvidence),
		Headline: "Answer from your own records",
		AnswerText: "Not evidenced by Patched. Patched collects evidence from your endpoints and holds nothing " +
			"that answers this question. Answer it from " + q.outOfScope + ".",
		Basis: "Outside the endpoint evidence Patched collects.",
	}
}

// --- shared helpers ---------------------------------------------------------

// insuranceReporting reports whether a CE reporting bucket means the device
// reported within InsuranceReportingWindow: active (24 hours) or stale (24
// hours to 14 days). silent and unknown (no usable report time) do not.
func insuranceReporting(bucket string) bool {
	return bucket == "active" || bucket == "stale"
}

func insuranceIntPtr(n int) *int { return &n }

// insurancePct is part over whole as a percentage to one decimal place, nil
// when there is no whole.
func insurancePct(part, whole int) *float64 {
	if whole <= 0 {
		return nil
	}
	p := math.Round(float64(part)/float64(whole)*1000) / 10
	return &p
}

// insuranceStatus: evidenced only when every in-scope device has a
// determinate answer, unknown when none has.
func insuranceStatus(determinate, unknown int) string {
	switch {
	case determinate == 0:
		return InsuranceUnknown
	case unknown > 0:
		return InsurancePartial
	}
	return InsuranceEvidenced
}

// insuranceFailed is the answer for a source that could not be read.
func insuranceFailed(err error, what string) InsuranceAnswer {
	reason := InsuranceReasonSourceUnavailable
	text := "Unknown. Patched could not read its " + what + " evidence when this pack was produced, so nothing is claimed. Produce the pack again later."
	if errors.Is(err, lifecycle.ErrEstateTooLarge) || errors.Is(err, remoteaccess.ErrEstateTooLarge) {
		reason = InsuranceReasonEstateTooLarge
		text = "Unknown. Your estate's software inventory is too large for Patched to assess in one pass, so nothing is claimed."
	}
	return InsuranceAnswer{
		Status: InsuranceUnknown, Reason: ceReason(reason), Headline: "Unknown", AnswerText: text,
		Basis: "Source unavailable when the pack was produced.",
	}
}

func insuranceNoDevices(asOf time.Time) InsuranceAnswer {
	return InsuranceAnswer{
		Status: InsuranceUnknown, Reason: ceReason(InsuranceReasonNoDevices), AsOf: &asOf,
		UnknownDevices: insuranceIntPtr(0), Headline: "Unknown",
		AnswerText: "Unknown. No devices in your estate report to Patched yet, so there is no evidence to answer from.",
		Basis:      "No in-scope devices.",
	}
}

// oldest tracks the oldest evidence time among the devices an answer used.
type insuranceOldest struct{ t *time.Time }

func (o *insuranceOldest) add(t *time.Time) {
	if t == nil {
		return
	}
	if o.t == nil || t.Before(*o.t) {
		u := t.UTC()
		o.t = &u
	}
}

func insPlural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func devicesWord(n int) string { return fmt.Sprintf("%d %s", n, insPlural(n, "device", "devices")) }

// insuranceUnknownClause renders the standard "unknown" sentence from its
// parts, skipping zero parts. parts are "N label" fragments in order.
func insuranceUnknownClause(total int, parts ...string) string {
	if total == 0 {
		return ""
	}
	var kept []string
	for _, p := range parts {
		if p != "" {
			kept = append(kept, p)
		}
	}
	return fmt.Sprintf(" %s %s unknown (%s) and %s not counted in your favour.",
		devicesWord(total), insPlural(total, "is", "are"), strings.Join(kept, "; "), insPlural(total, "is", "are"))
}

// insurancePart is one "N did something" fragment, with the verb phrase in
// its singular (one) or plural (many) form; empty when n is zero.
func insurancePart(n int, one, many string) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("%d %s", n, insPlural(n, one, many))
}

// --- answers ---------------------------------------------------------------

// insuranceEDR reads FetchEDRCoverageReport's per-device state. There is no
// "confirmed without EDR" state in that model (absence requires authority),
// so every in-scope device that is not covered is unknown.
func insuranceEDR(s *insuranceSources) InsuranceAnswer {
	if s.edr == nil {
		return insuranceFailed(s.edrErr, "EDR coverage")
	}
	asOf := s.edr.GeneratedAt
	if len(s.scope) == 0 {
		return insuranceNoDevices(asOf)
	}
	byID := make(map[string]EDRState, len(s.edr.Devices))
	for _, d := range s.edr.Devices {
		byID[d.DeviceID] = d.State
	}
	var covered, unrecognised, noEvidence, notReporting int
	var oldest insuranceOldest
	for _, d := range s.scope {
		if !insuranceReporting(d.Reporting.Bucket) {
			notReporting++
			continue
		}
		switch byID[d.DeviceID] {
		case EDRStateCovered:
			covered++
			oldest.add(d.Reporting.ObservedAt)
		case EDRStateUnrecognised:
			unrecognised++
		default:
			noEvidence++
		}
	}
	total := len(s.scope)
	unknown := unrecognised + noEvidence + notReporting
	pct := insurancePct(covered, total)
	text := fmt.Sprintf("%d of %s (%.1f%%) %s endpoint protection that Patched recognises.", covered, devicesWord(total), *pct,
		insPlural(covered, "reports", "report"))
	text += insuranceUnknownClause(unknown,
		insurancePart(unrecognised, "reported a security tool Patched does not recognise", "reported a security tool Patched does not recognise"),
		insurancePart(noEvidence, "reported no security tool evidence", "reported no security tool evidence"),
		insurancePart(notReporting, "has not reported in the last 14 days", "have not reported in the last 14 days"))
	return InsuranceAnswer{
		Status: insuranceStatus(covered, unknown),
		Answer: InsuranceValue{Value: insuranceIntPtr(covered), Unit: "devices", Percentage: pct, Counts: map[string]int{
			"devices_in_scope": total, "covered": covered, "unrecognised_tool": unrecognised,
			"no_evidence": noEvidence, "not_reporting": notReporting,
		}},
		UnknownDevices: insuranceIntPtr(unknown), AsOf: &asOf, OldestEvidenceAt: oldest.t,
		Headline:   fmt.Sprintf("%d of %d devices (%.1f%%)", covered, total, *pct),
		AnswerText: text,
		Basis: "Security tools each device reported, matched against the endpoint protection products Patched recognises " +
			"and any you have added. Only a recognised product counts. A device that has not reported in the last 14 days is unknown.",
	}
}

// insuranceNamedDevicesCap is how many devices an answer names before it
// counts the rest.
const insuranceNamedDevicesCap = 10

// insuranceNoHostname stands in for a device with no hostname. It is the
// placeholder the EDR coverage report, one of the pack's sources, already uses
// for a nameless device, so no item is ever empty.
const insuranceNoHostname = "(no hostname)"

// insuranceDeviceLabel is how a device is shown in an answer: its hostname with
// control characters turned into spaces and runs of space collapsed, or
// insuranceNoHostname when nothing is left. A hostname is agent-supplied, so it
// cannot break the sentence it sits in. It is otherwise left exactly as the
// device reported it; the CSV and PDF writers apply their own escaping to the
// whole answer text (the CSV formula guard acts on the first character of a
// cell, which here is never a hostname).
func insuranceDeviceLabel(hostname string) string {
	clean := strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, hostname)), " ")
	if clean == "" {
		return insuranceNoHostname
	}
	return clean
}

// insuranceDevicesNamed renders "<lead>: A, B, C." for the given hostnames,
// sorted without regard to case, naming at most insuranceNamedDevicesCap and
// ending "and N more" for the rest ("<lead>: A, B ... J and 3 more.").
func insuranceDevicesNamed(lead string, hostnames []string) string {
	labels := make([]string, len(hostnames))
	for i, h := range hostnames {
		labels[i] = insuranceDeviceLabel(h)
	}
	sort.Slice(labels, func(i, j int) bool {
		li, lj := strings.ToLower(labels[i]), strings.ToLower(labels[j])
		if li != lj {
			return li < lj
		}
		return labels[i] < labels[j]
	})
	more := 0
	if len(labels) > insuranceNamedDevicesCap {
		more = len(labels) - insuranceNamedDevicesCap
		labels = labels[:insuranceNamedDevicesCap]
	}
	out := lead + ": " + strings.Join(labels, ", ")
	if more > 0 {
		out += fmt.Sprintf(" and %d more", more)
	}
	return out + "."
}

// insuranceEncryption reads each device's State from the encryption posture
// report, which takes it from FetchEncryptionStates, the one definition the
// roster and the device page share (PAT-2496). A device the report does not
// carry is unknown.
func insuranceEncryption(s *insuranceSources) InsuranceAnswer {
	if s.enc == nil {
		return insuranceFailed(s.encErr, "disk encryption")
	}
	asOf := s.enc.GeneratedAt
	if len(s.scope) == 0 {
		return insuranceNoDevices(asOf)
	}
	byID := make(map[string]string, len(s.enc.Devices))
	for _, d := range s.enc.Devices {
		byID[d.DeviceID] = d.State
	}
	var encrypted, notEncrypted, noEvidence, notReporting int
	var off []string // hostnames of the in-scope, reporting devices observed off
	var oldest insuranceOldest
	for _, d := range s.scope {
		if !insuranceReporting(d.Reporting.Bucket) {
			notReporting++
			continue
		}
		switch byID[d.DeviceID] {
		case EncryptionStateEncrypted:
			encrypted++
			oldest.add(d.Reporting.ObservedAt)
		case EncryptionStateNotEncrypted:
			notEncrypted++
			off = append(off, d.Hostname)
			oldest.add(d.Reporting.ObservedAt)
		default:
			noEvidence++
		}
	}
	total := len(s.scope)
	unknown := noEvidence + notReporting
	pct := insurancePct(encrypted, total)
	text := fmt.Sprintf("%d of %s (%.1f%%) %s FileVault or BitLocker full-disk encryption turned on.", encrypted, devicesWord(total), *pct,
		insPlural(encrypted, "reports", "report"))
	if notEncrypted > 0 {
		text += fmt.Sprintf(" %s %s encryption turned off.", devicesWord(notEncrypted), insPlural(notEncrypted, "reports", "report"))
		text += " " + insuranceDevicesNamed("Encryption is turned off on", off)
	}
	text += insuranceUnknownClause(unknown,
		insurancePart(noEvidence, "reported no encryption state", "reported no encryption state"),
		insurancePart(notReporting, "has not reported in the last 14 days", "have not reported in the last 14 days"))
	return InsuranceAnswer{
		Status: insuranceStatus(encrypted+notEncrypted, unknown),
		Answer: InsuranceValue{Value: insuranceIntPtr(encrypted), Unit: "devices", Percentage: pct, Counts: map[string]int{
			"devices_in_scope": total, "encrypted": encrypted, "not_encrypted": notEncrypted,
			"no_evidence": noEvidence, "not_reporting": notReporting,
		}},
		UnknownDevices: insuranceIntPtr(unknown), AsOf: &asOf, OldestEvidenceAt: oldest.t,
		Headline:   fmt.Sprintf("%d of %d devices (%.1f%%)", encrypted, total, *pct),
		AnswerText: text,
		Basis: "The latest result of the FileVault (macOS) or BitLocker (Windows) check on each device's system disk, " +
			"the same result the Devices page shows. A device that reported no readable state, or that has not reported " +
			"in the last 14 days, is unknown.",
	}
}

// insurancePatching reads the CE readiness items and evidence per device:
// items are confirmed critical or high findings past 14 days; a device with
// none is only "none evidenced" when CE readiness has complete, current CVE
// evidence for it (reported within 24 hours, matching complete).
func insurancePatching(s *insuranceSources) InsuranceAnswer {
	asOf := s.ce.GeneratedAt
	if len(s.scope) == 0 {
		return insuranceNoDevices(asOf)
	}
	var items14, items30, crit14, high14, dev14, dev30, noneEvidenced, unknown int
	var oldest insuranceOldest
	for _, d := range s.scope {
		if len(d.Items) > 0 {
			dev14++
			over30 := false
			for _, it := range d.Items {
				items14++
				if it.Severity == "critical" {
					crit14++
				} else {
					high14++
				}
				if it.AgeDays > 30 {
					items30++
					over30 = true
				}
			}
			if over30 {
				dev30++
			}
			oldest.add(d.Reporting.ObservedAt)
			continue
		}
		if d.Reporting.Bucket != "active" || d.CVEEvidence.State != CEEvidenceEvidenced {
			unknown++
			continue
		}
		noneEvidenced++
		oldest.add(d.Reporting.ObservedAt)
	}
	total := len(s.scope)
	var text string
	switch {
	case items14 == 0 && noneEvidenced == 0:
		text = fmt.Sprintf("None of the %s has complete, current vulnerability evidence, so Patched cannot say whether any update is outstanding.",
			devicesWord(total))
	case items14 == 0:
		text = fmt.Sprintf("No critical or high severity update was found outstanding for more than 14 days on the %d of %s with current evidence.",
			noneEvidenced, devicesWord(total))
	default:
		text = fmt.Sprintf("%d critical or high severity %s (%d critical, %d high) %s outstanding for more than 14 days across %d of %s, "+
			"of which %d %s outstanding for more than 30 days across %s. %d of %s %s nothing outstanding.",
			items14, insPlural(items14, "update", "updates"), crit14, high14, insPlural(items14, "is", "are"), dev14, devicesWord(total),
			items30, insPlural(items30, "is", "are"), devicesWord(dev30), noneEvidenced, devicesWord(total), insPlural(noneEvidenced, "shows", "show"))
	}
	if unknown > 0 && !(items14 == 0 && noneEvidenced == 0) {
		text += fmt.Sprintf(" %s %s unknown because %s not reported in the last 24 hours or %s vulnerability matching is not complete, and %s not counted in your favour.",
			devicesWord(unknown), insPlural(unknown, "is", "are"), insPlural(unknown, "it has", "they have"), insPlural(unknown, "its", "their"), insPlural(unknown, "is", "are"))
	}
	headline := fmt.Sprintf("%d over 14 days, %d over 30 days", items14, items30)
	switch {
	case items14 == 0 && noneEvidenced == 0:
		headline = "Unknown"
	case items14 == 0:
		headline = fmt.Sprintf("None found on %d of %d devices", noneEvidenced, total)
	}
	return InsuranceAnswer{
		Status: insuranceStatus(dev14+noneEvidenced, unknown), Headline: headline,
		Answer: InsuranceValue{Value: insuranceIntPtr(items14), Unit: "updates", Percentage: nil, Counts: map[string]int{
			"devices_in_scope": total, "updates_over_14_days": items14, "updates_over_30_days": items30,
			"critical_over_14_days": crit14, "high_over_14_days": high14,
			"devices_over_14_days": dev14, "devices_over_30_days": dev30,
			"devices_none_outstanding": noneEvidenced, "devices_unknown": unknown,
		}},
		UnknownDevices: insuranceIntPtr(unknown), AsOf: &asOf, OldestEvidenceAt: oldest.t,
		AnswerText: text,
		Basis: "Confirmed vulnerability matches against the software each device reported, counted from the date each " +
			"advisory was published, which can make an update look older than the vendor's fix. Operating system " +
			"update status is not yet evidenced at version level and is not included.",
	}
}

// insuranceUnsupported reads the unsupported software report's rows.
func insuranceUnsupported(s *insuranceSources) InsuranceAnswer {
	if s.life == nil {
		return insuranceFailed(s.lifErr, "software support")
	}
	rep := s.life
	asOf := rep.GeneratedAt
	b := rep.Basis
	if b.DevicesAssessed == 0 {
		return insuranceNoDevices(asOf)
	}
	osUnsupported, osUnknown := map[string]bool{}, map[string]bool{}
	appUnsupported, anyUnknown := map[string]bool{}, map[string]bool{}
	appUnsupportedInstalls := 0
	for _, r := range rep.Rows {
		switch r.State {
		case lifecycle.StateUnsupported:
			if r.Kind == lifecycle.KindOperatingSystem {
				osUnsupported[r.DeviceID] = true
			} else {
				appUnsupported[r.DeviceID] = true
				appUnsupportedInstalls++
			}
		case lifecycle.StateUnknown:
			anyUnknown[r.DeviceID] = true
			if r.Kind == lifecycle.KindOperatingSystem {
				osUnknown[r.DeviceID] = true
			}
		}
	}
	for _, id := range b.UnassessedDeviceIDs {
		anyUnknown[id] = true
	}
	withUnsupported := map[string]bool{}
	for id := range osUnsupported {
		withUnsupported[id] = true
	}
	for id := range appUnsupported {
		withUnsupported[id] = true
	}
	// A device with positive evidence of unsupported software answers the
	// question for that device even if other software on it is unknown;
	// every other device with any unknown row, stale evidence or no
	// inventory is unknown.
	unknown := 0
	for id := range anyUnknown {
		if !withUnsupported[id] {
			unknown++
		}
	}
	text := fmt.Sprintf("%d of %s %s an operating system past its vendor's end of support, and %s %s software past end of support (%d %s).",
		len(osUnsupported), devicesWord(b.DevicesAssessed), insPlural(len(osUnsupported), "runs", "run"),
		devicesWord(len(appUnsupported)), insPlural(len(appUnsupported), "has", "have"),
		appUnsupportedInstalls, insPlural(appUnsupportedInstalls, "installation", "installations"))
	if unknown > 0 {
		text += fmt.Sprintf(" The other %s %s unknown: support could not be established for some or all of %s software "+
			"(%d for the operating system itself), or %s evidence is more than 14 days old or has no software inventory. "+
			"Unknown never means supported.",
			devicesWord(unknown), insPlural(unknown, "is", "are"), insPlural(unknown, "its", "their"), len(osUnknown), insPlural(unknown, "its", "their"))
	}
	status := insuranceStatus(b.DevicesAssessed-unknown, unknown)
	return InsuranceAnswer{
		Status: status, Headline: fmt.Sprintf("%d of %d devices", len(withUnsupported), b.DevicesAssessed),
		Answer: InsuranceValue{Value: insuranceIntPtr(len(withUnsupported)), Unit: "devices",
			Percentage: insurancePct(len(withUnsupported), b.DevicesAssessed), Counts: map[string]int{
				"devices_assessed": b.DevicesAssessed, "devices_unsupported_os": len(osUnsupported),
				"devices_os_support_unknown": len(osUnknown), "devices_unsupported_software": len(appUnsupported),
				"unsupported_software_installations": appUnsupportedInstalls,
				"devices_with_any_unsupported":       len(withUnsupported), "devices_unknown": unknown,
				"devices_stale": b.DevicesStale, "devices_without_inventory": b.DevicesWithoutInventory,
			}},
		UnknownDevices: insuranceIntPtr(unknown), AsOf: &asOf, OldestEvidenceAt: b.EvidenceOldestAt,
		AnswerText: text,
		Basis: "Operating system and software versions each device reported, compared with public end of support dates " +
			"from endoflife.date through a reviewed mapping. A product with no reviewed mapping is unknown, never supported.",
	}
}

// insuranceLocalAdmin reads the local admin report's per-device count and
// risk band.
func insuranceLocalAdmin(s *insuranceSources) InsuranceAnswer {
	if s.admin == nil {
		return insuranceFailed(s.admErr, "local administrator")
	}
	asOf := s.admin.GeneratedAt
	if len(s.scope) == 0 {
		return insuranceNoDevices(asOf)
	}
	byID := make(map[string]LocalAdminDevice, len(s.admin.Devices))
	for _, d := range s.admin.Devices {
		byID[d.DeviceID] = d
	}
	var withCount, accounts, within, atRisk, critical, builtinEnabled, noEvidence, notReporting int
	names := map[string]bool{}
	var oldest insuranceOldest
	for _, d := range s.scope {
		if !insuranceReporting(d.Reporting.Bucket) {
			notReporting++
			continue
		}
		dev, ok := byID[d.DeviceID]
		// An enabled built-in Administrator is an observed failure whether or
		// not the device also reported an admin count (PAT-2496), so it is
		// counted before a missing count sets the device aside as unknown.
		// A built-in account whose state was not established is not an
		// observation (BuiltinAdminUnknown) and is not counted.
		if ok && dev.BuiltinAdmin == BuiltinAdminEnabled {
			builtinEnabled++
			oldest.add(d.Reporting.ObservedAt)
		}
		if !ok || dev.AdminCount < 0 || dev.Risk == "unknown" {
			noEvidence++
			continue
		}
		withCount++
		accounts += dev.AdminCount
		switch dev.Risk {
		case "compliant":
			within++
		case "at-risk":
			atRisk++
		default:
			critical++
		}
		for _, n := range dev.AdminNames {
			names[strings.ToLower(n)] = true
		}
		oldest.add(d.Reporting.ObservedAt)
	}
	total := len(s.scope)
	unknown := noEvidence + notReporting
	text := fmt.Sprintf("%d local administrator %s across the %d of %s that reported an admin count (an account present on two devices counts twice). "+
		"%s %s 2 or fewer, %d %s 3 or 4, and %d %s 5 or more.",
		accounts, insPlural(accounts, "account", "accounts"), withCount, devicesWord(total),
		devicesWord(within), insPlural(within, "has", "have"), atRisk, insPlural(atRisk, "has", "have"), critical, insPlural(critical, "has", "have"))
	if builtinEnabled > 0 {
		text += fmt.Sprintf(" %s %s the built-in Windows Administrator account enabled.", devicesWord(builtinEnabled), insPlural(builtinEnabled, "has", "have"))
	}
	text += insuranceUnknownClause(unknown,
		insurancePart(noEvidence, "reported no admin count", "reported no admin count"),
		insurancePart(notReporting, "has not reported in the last 14 days", "have not reported in the last 14 days"))
	return InsuranceAnswer{
		Status:   insuranceStatus(withCount, unknown),
		Headline: fmt.Sprintf("%d %s on %d of %d devices", accounts, insPlural(accounts, "account", "accounts"), withCount, total),
		Answer: InsuranceValue{Value: insuranceIntPtr(accounts), Unit: "accounts", Percentage: nil, Counts: map[string]int{
			"devices_in_scope": total, "devices_with_count": withCount, "admin_accounts": accounts,
			"devices_2_or_fewer": within, "devices_3_to_4": atRisk, "devices_5_or_more": critical,
			"devices_builtin_admin_enabled": builtinEnabled, "distinct_account_names": len(names),
			"no_evidence": noEvidence, "not_reporting": notReporting,
		}},
		UnknownDevices: insuranceIntPtr(unknown), AsOf: &asOf, OldestEvidenceAt: oldest.t,
		AnswerText: text,
		Basis: "Accounts in each device's local administrators group when it last reported. A disabled built-in Windows " +
			"Administrator is not counted. Patched cannot tell whether an account's rights are time-limited, so every " +
			"member is counted as standing.",
	}
}

// insuranceRemoteAccess reads the remote access report's summary. Its
// detection is limited to the tools Patched's catalogue recognises, so the
// answer is never better than partial.
func insuranceRemoteAccess(s *insuranceSources) InsuranceAnswer {
	if s.remote == nil {
		return insuranceFailed(s.remErr, "remote access")
	}
	rep := s.remote
	asOf := rep.GeneratedAt
	b := rep.Basis
	if b.DevicesAssessed == 0 {
		return insuranceNoDevices(asOf)
	}
	sum := rep.Summary
	st := func(state string) int { return sum.RemoteAccess[state].Tools }
	devices := map[string]bool{}
	for _, r := range rep.Rows {
		if r.Category == remoteaccess.CategoryRemoteAccess {
			devices[r.DeviceID] = true
		}
	}
	unknown := len(b.UnassessedDeviceIDs)
	approved, unapproved, unreviewed, ignored := st(remoteaccess.StateApproved), st(remoteaccess.StateUnapproved),
		st(remoteaccess.StateUnreviewed), st(remoteaccess.StateIgnored)
	var text string
	if sum.RemoteAccessToolCount == 0 {
		text = fmt.Sprintf("Patched found none of the remote access tools it recognises on the %s assessed.", devicesWord(b.DevicesAssessed))
	} else {
		text = fmt.Sprintf("Patched found %d remote access %s on %d of %s: %d approved by your organisation, %d unapproved, %d not yet reviewed and %d ignored.",
			sum.RemoteAccessToolCount, insPlural(sum.RemoteAccessToolCount, "tool", "tools"), len(devices), devicesWord(b.DevicesAssessed),
			approved, unapproved, unreviewed, ignored)
	}
	if sum.RMMAgentToolCount > 0 {
		text += fmt.Sprintf(" Remote monitoring and management agents (%d) are counted separately.", sum.RMMAgentToolCount)
	}
	text += " Detection covers only the tools Patched recognises, so finding none is not proof that none is installed."
	if unknown > 0 {
		text += fmt.Sprintf(" %s %s unknown because %s not reported in the last 14 days or %s no software inventory.",
			devicesWord(unknown), insPlural(unknown, "is", "are"), insPlural(unknown, "it has", "they have"), insPlural(unknown, "reports", "report"))
	}
	status := insuranceStatus(b.DevicesAssessed-unknown, unknown)
	var reason *string
	if status == InsuranceEvidenced {
		status, reason = InsurancePartial, ceReason(InsuranceReasonCatalogueLimited)
	}
	return InsuranceAnswer{
		Status: status, Reason: reason,
		Headline: fmt.Sprintf("%d %s found, %d approved", sum.RemoteAccessToolCount, insPlural(sum.RemoteAccessToolCount, "tool", "tools"), approved),
		Answer: InsuranceValue{Value: insuranceIntPtr(sum.RemoteAccessToolCount), Unit: "tools", Percentage: nil, Counts: map[string]int{
			"devices_assessed": b.DevicesAssessed, "tools_found": sum.RemoteAccessToolCount,
			"devices_with_tools": len(devices), "approved_tools": approved, "unapproved_tools": unapproved,
			"unreviewed_tools": unreviewed, "ignored_tools": ignored, "rmm_agent_tools": sum.RMMAgentToolCount,
			"devices_unknown": unknown,
		}},
		UnknownDevices: insuranceIntPtr(unknown), AsOf: &asOf, OldestEvidenceAt: b.EvidenceOldestAt,
		AnswerText: text,
		Basis: "Software and browser extensions each device reported, matched against Patched's catalogue of remote " +
			"access tools. Approved means your organisation marked the product Approved in Patched.",
	}
}

// insuranceAssetInventory reads the CE readiness device list and reporting
// buckets.
func insuranceAssetInventory(s *insuranceSources) InsuranceAnswer {
	asOf := s.ce.GeneratedAt
	total := len(s.scope)
	if total == 0 {
		return insuranceNoDevices(asOf)
	}
	buckets := map[string]int{}
	var oldest insuranceOldest
	for _, d := range s.scope {
		buckets[d.Reporting.Bucket]++
		if insuranceReporting(d.Reporting.Bucket) {
			oldest.add(d.Reporting.ObservedAt)
		}
	}
	reporting := buckets["active"] + buckets["stale"]
	unknown := total - reporting
	pct := insurancePct(reporting, total)
	text := fmt.Sprintf("Patched holds an inventory of %s running its agent", devicesWord(total))
	if r := s.ce.Estate.RetiredExcluded; r > 0 {
		text += fmt.Sprintf(", not counting %s your organisation has retired", devicesWord(r))
	}
	text += fmt.Sprintf(". %d reported in the last 24 hours and %d in the last 14 days (%.1f%% of the estate reporting).",
		buckets["active"], reporting, *pct)
	if unknown > 0 {
		text += fmt.Sprintf(" %s %s not reported for more than 14 days or %s no usable report time.",
			devicesWord(unknown), insPlural(unknown, "has", "have"), insPlural(unknown, "has", "have"))
	}
	text += " Devices without the Patched agent are not in this count, so it is not a complete asset register."
	return InsuranceAnswer{
		Status:   insuranceStatus(reporting, unknown),
		Headline: fmt.Sprintf("%d devices, %d reporting (%.1f%%)", total, reporting, *pct),
		Answer: InsuranceValue{Value: insuranceIntPtr(total), Unit: "devices", Percentage: pct, Counts: map[string]int{
			"devices_in_scope": total, "reported_24_hours": buckets["active"], "reported_14_days": reporting,
			"not_reporting": buckets["silent"], "no_report_time": buckets["unknown"],
			"retired_excluded": s.ce.Estate.RetiredExcluded,
		}},
		UnknownDevices: insuranceIntPtr(unknown), AsOf: &asOf, OldestEvidenceAt: oldest.t,
		AnswerText: text,
		Basis: "Every device running the Patched agent on a platform enabled for your estate, less any your organisation retired, " +
			"with the time each last reported.",
	}
}

// InsuranceCountsString renders Counts as "key=value" pairs sorted by key,
// joined with ";", for the CSV export.
func InsuranceCountsString(c map[string]int) string {
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s=%d", k, c[k])
	}
	return strings.Join(parts, ";")
}
