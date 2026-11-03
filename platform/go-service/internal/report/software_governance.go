package report

// PAT-2009 software governance reports: New Software, Unapproved and
// Unreviewed Software (drift, including the Unapproved-present list), and the
// Approved Software List. Data comes from internal/softwaregov, the same
// functions behind the portal JSON and CSV endpoints, so the PDF, the CSV and
// the screen can never disagree.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/softwaregov"
)

// NewSoftwareReport is the New Software report: products first seen since
// the tenant's last approval review.
type NewSoftwareReport struct {
	Tenant      string
	GeneratedAt time.Time
	Data        softwaregov.NewSoftware
}

// SoftwareDriftReport is the Unapproved and Unreviewed Software report.
type SoftwareDriftReport struct {
	Tenant      string
	GeneratedAt time.Time
	Data        softwaregov.Drift
}

// ApprovedSoftwareReport is the Approved Software List.
type ApprovedSoftwareReport struct {
	Tenant      string
	GeneratedAt time.Time
	Data        softwaregov.ApprovedList
}

func governanceTenantName(ctx context.Context, pool *pgxpool.Pool, tenantID string) (string, error) {
	var name string
	err := pool.QueryRow(ctx, `SELECT name FROM tenants WHERE id = $1::uuid`, tenantID).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrTenantNotFound
	}
	if err != nil {
		return "", fmt.Errorf("fetch tenant: %w", err)
	}
	return name, nil
}

// FetchNewSoftwareReport builds the New Software report from the last review.
func FetchNewSoftwareReport(ctx context.Context, pool *pgxpool.Pool, tenantID string) (NewSoftwareReport, error) {
	now := time.Now().UTC()
	name, err := governanceTenantName(ctx, pool, tenantID)
	if err != nil {
		return NewSoftwareReport{}, err
	}
	data, err := softwaregov.FetchNewSoftware(ctx, pool, tenantID, nil, now)
	if err != nil {
		return NewSoftwareReport{}, err
	}
	return NewSoftwareReport{Tenant: name, GeneratedAt: now, Data: data}, nil
}

// FetchSoftwareDriftReport builds the drift report.
func FetchSoftwareDriftReport(ctx context.Context, pool *pgxpool.Pool, tenantID string) (SoftwareDriftReport, error) {
	now := time.Now().UTC()
	name, err := governanceTenantName(ctx, pool, tenantID)
	if err != nil {
		return SoftwareDriftReport{}, err
	}
	data, err := softwaregov.FetchDrift(ctx, pool, tenantID, now)
	if err != nil {
		return SoftwareDriftReport{}, err
	}
	return SoftwareDriftReport{Tenant: name, GeneratedAt: now, Data: data}, nil
}

// FetchApprovedSoftwareReport builds the Approved Software List.
func FetchApprovedSoftwareReport(ctx context.Context, pool *pgxpool.Pool, tenantID string) (ApprovedSoftwareReport, error) {
	now := time.Now().UTC()
	name, err := governanceTenantName(ctx, pool, tenantID)
	if err != nil {
		return ApprovedSoftwareReport{}, err
	}
	data, err := softwaregov.FetchApproved(ctx, pool, tenantID, now)
	if err != nil {
		return ApprovedSoftwareReport{}, err
	}
	return ApprovedSoftwareReport{Tenant: name, GeneratedAt: now, Data: data}, nil
}

// Governance PDF row caps. The CSV export carries every row.
const (
	governancePDFMaxRows    = 300
	governancePDFMaxDevices = 8
)

type governancePDF struct {
	pdf *fpdf.Fpdf
}

func newGovernancePDF(title, tenant string, generated time.Time, audience ReportAudience) (*governancePDF, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(leftMargin, topMargin, rightMargin)
	pdf.SetAutoPageBreak(true, bottomMargin)
	pdf.SetTitle("Patched: "+title, true)
	pdf.SetAuthor("patched.im", true)
	pdf.SetCreator("patched-api report renderer", true)
	registerReportFont(pdf)
	// PAT-2264: customer downloads never draw header.png, so skip
	// registering it at all -- fpdf embeds every registered image
	// regardless of use, and the retired pixel-P asset has no business
	// riding along inertly in a document that leaves the building.
	if audience != AudienceCustomer {
		if err := registerHeader(pdf); err != nil {
			return nil, err
		}
	}
	// PAT-2265: no UnicodeTranslatorFromDescriptor step here. That helper
	// maps a UTF-8 string down to a single-byte legacy codepage for use with
	// a core font (Helvetica); reportFont is a real UTF-8 TrueType font
	// registered via AddUTF8FontFromBytes, so text is passed through as-is.
	// Running it through the byte-encoded translator anyway is exactly what
	// produced the "â€..." mojibake this ticket fixes, and it also can't
	// represent ≤/≥ at all (outside cp1252's repertoire).
	g := &governancePDF{pdf: pdf}
	pdf.SetFooterFunc(func() {
		pdf.SetY(-10)
		pdf.SetFont("Helvetica", "", 8)
		setTextColour(pdf, colourMuted)
		pdf.CellFormat(0, 6, fmt.Sprintf("Page %d / {nb}", pdf.PageNo()), "", 0, "C", false, 0, "")
	})
	pdf.AliasNbPages("")
	pdf.AddPage()

	imageWidth := 80.0
	// PAT-2264: customer portal downloads never carry the "Staff report"
	// caption baked into header.png; they get the current in-app brand
	// mark instead. Staff/admin routes are untouched.
	if audience == AudienceCustomer {
		pdf.SetY(drawCustomerHeaderMark(pdf, imageWidth))
	} else {
		pdf.ImageOptions("header.png", (210.0-imageWidth)/2, topMargin, imageWidth, 0, false,
			fpdf.ImageOptions{ImageType: "PNG"}, 0, "")
		pdf.SetY(topMargin + imageWidth*0.6 + 3)
	}
	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 5, "Endpoint Assurance  |  Software Governance", "", 1, "C", false, 0, "")
	pdf.Ln(2)
	hrule(pdf, 0.6)
	pdf.Ln(4)
	pdf.SetFont(reportFont, "B", 18)
	setTextColour(pdf, colourBodyText)
	pdf.CellFormat(0, 10, title, "", 1, "C", false, 0, "")
	pdf.Ln(1)
	pdf.SetFont(reportFont, "", 10)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 5, "Prepared for", "", 1, "C", false, 0, "")
	pdf.SetFont(reportFont, "B", 13)
	setTextColour(pdf, colourBodyText)
	pdf.CellFormat(0, 7, fallback(tenant), "", 1, "C", false, 0, "")
	pdf.SetFont(reportFont, "", 9)
	pdf.CellFormat(0, 5, "Report Date: "+generated.Format("02 Jan 2006"), "", 1, "C", false, 0, "")
	pdf.CellFormat(0, 5, "Classification: Confidential", "", 1, "C", false, 0, "")
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 5, "Prepared by Patched.im Ltd  |  patched.im", "", 1, "C", false, 0, "")
	pdf.Ln(2)
	hrule(pdf, 0.4)
	pdf.Ln(4)
	return g, nil
}

func (g *governancePDF) para(text string) {
	g.pdf.SetFont(reportFont, "", 9)
	setTextColour(g.pdf, colourBodyText)
	g.pdf.MultiCell(0, 4.5, text, "", "L", false)
	g.pdf.Ln(2)
}

func (g *governancePDF) note(text string) {
	g.pdf.SetFont(reportFont, "I", 9)
	setTextColour(g.pdf, colourMuted)
	g.pdf.MultiCell(0, 4.5, text, "", "L", false)
	g.pdf.Ln(2)
}

func (g *governancePDF) table(labels []string, widths []float64, rows [][]string) {
	tableHeader(g.pdf, labels, widths)
	tableBody(g.pdf, rows, widths, true)
	g.pdf.Ln(3)
}

func (g *governancePDF) coverage(c softwaregov.Coverage) {
	text := fmt.Sprintf("Evidence: %d devices, %d reported in the last %d days.", c.DevicesTotal, c.DevicesReporting, c.StaleAfterDays)
	if c.DevicesStale > 0 {
		text += fmt.Sprintf(" %d devices have not reported for over %d days, so their software may have changed since.", c.DevicesStale, c.StaleAfterDays)
	}
	if c.DevicesWithoutInventory > 0 {
		text += fmt.Sprintf(" %d devices have reported no applications, so nothing about their software can be concluded.", c.DevicesWithoutInventory)
	}
	// PAT-2135: retired devices are the customer's decision, not missing
	// evidence, and are not counted in the figures above.
	if c.DevicesRetired > 0 {
		text += fmt.Sprintf(" %d retired device%s, retired by your organisation, not counted as reporting or stale.", c.DevicesRetired, plural(c.DevicesRetired))
	}
	if !c.Complete {
		text += " This report therefore does not cover the whole estate."
	}
	g.note(text)
}

func (g *governancePDF) closer(title string, generated time.Time) ([]byte, error) {
	pdf := g.pdf
	pdf.Ln(4)
	hrule(pdf, 0.4)
	pdf.Ln(3)
	g.para("This " + title + " was generated by Patched.im Ltd from inventory reported by the Patched endpoint agent. " +
		"Patched reports software. It does not install or remove it.")
	pdf.SetFont(reportFont, "I", 8)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 4.5, "Generated: "+generated.Format("02 Jan 2006 15:04 MST")+"  |  patched.im", "", 1, "L", false, 0, "")
	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("write %s pdf: %w", strings.ToLower(title), err)
	}
	return buf.Bytes(), nil
}

func govPlatform(p softwaregov.Product) string {
	if p.Type == softwaregov.TypeBrowserExtension {
		return p.Browser + " extension"
	}
	switch p.Platform {
	case "macos":
		return "macOS"
	case "windows":
		return "Windows"
	}
	return p.Platform
}

func govIdentifier(p softwaregov.Product) string {
	if p.Type == softwaregov.TypeBrowserExtension {
		return p.ExtensionID
	}
	return p.Identifier
}

func govDate(t time.Time) string {
	if t.IsZero() {
		return "not recorded"
	}
	return t.UTC().Format("02 Jan 2006")
}

// RenderNewSoftwarePDF renders the New Software report for staff/admin use.
// Header carries the internal header.png mark, unchanged.
func RenderNewSoftwarePDF(d NewSoftwareReport) ([]byte, error) {
	return renderNewSoftwarePDF(d, AudienceStaff)
}

// RenderNewSoftwarePDFCustomer renders the same New Software report for a
// customer's own portal download (PAT-2264). The only difference from
// RenderNewSoftwarePDF is the header: no "Staff report" wording and the
// current in-app brand mark instead of the retired pixel-P baked into
// header.png. Every other section, colour, font and layout is shared.
func RenderNewSoftwarePDFCustomer(d NewSoftwareReport) ([]byte, error) {
	return renderNewSoftwarePDF(d, AudienceCustomer)
}

func renderNewSoftwarePDF(d NewSoftwareReport, audience ReportAudience) ([]byte, error) {
	const title = "New Software Report"
	g, err := newGovernancePDF(title, d.Tenant, d.GeneratedAt, audience)
	if err != nil {
		return nil, err
	}
	ns := d.Data
	switch ns.SinceBasis {
	case softwaregov.SinceNoReview:
		g.para("No software approval review has been recorded yet, so every product the estate has reported is listed as new.")
	default:
		if ns.Since != nil {
			g.para("Products first reported by any device since the last software approval review on " +
				ns.Since.UTC().Format("02 Jan 2006 15:04 UTC") + ".")
		}
	}
	g.coverage(ns.Coverage)
	sectionHeader(g.pdf, fmt.Sprintf("%d new products", ns.Total))
	if len(ns.Products) == 0 {
		g.note("No product was first reported in this period.")
		return g.closer(title, d.GeneratedAt)
	}
	rows := make([][]string, 0, len(ns.Products))
	for i, p := range ns.Products {
		if i >= governancePDFMaxRows {
			break
		}
		name := p.Name
		if p.IdentityBasis == "name_only" {
			name += " (name only)"
		}
		rows = append(rows, []string{
			truncate(name, 34), truncate(p.Platform, 10), govDate(p.FirstSeenAt),
			fmt.Sprintf("%d", p.DeviceCount), truncate(p.FirstDevice.Hostname, 26), p.ApprovalState,
		})
	}
	g.table([]string{"Product", "Platform", "First seen", "Devices", "First device", "State"},
		[]float64{50, 18, 24, 16, 40, 26}, rows)
	if ns.Total > len(rows) {
		g.note(fmt.Sprintf("%d further products are in the CSV export.", ns.Total-len(rows)))
	}
	return g.closer(title, d.GeneratedAt)
}

// RenderSoftwareDriftPDF renders the Unapproved and Unreviewed Software
// report, including the Unapproved-present list, for staff/admin use.
// Header carries the internal header.png mark, unchanged.
func RenderSoftwareDriftPDF(d SoftwareDriftReport) ([]byte, error) {
	return renderSoftwareDriftPDF(d, AudienceStaff)
}

// RenderSoftwareDriftPDFCustomer renders the same Unapproved and Unreviewed
// Software report for a customer's own portal download (PAT-2264). The
// only difference from RenderSoftwareDriftPDF is the header: no "Staff
// report" wording and the current in-app brand mark instead of the retired
// pixel-P baked into header.png. Every other section, colour, font and
// layout is shared.
func RenderSoftwareDriftPDFCustomer(d SoftwareDriftReport) ([]byte, error) {
	return renderSoftwareDriftPDF(d, AudienceCustomer)
}

func renderSoftwareDriftPDF(d SoftwareDriftReport, audience ReportAudience) ([]byte, error) {
	const title = "Unapproved and Unreviewed Software Report"
	g, err := newGovernancePDF(title, d.Tenant, d.GeneratedAt, audience)
	if err != nil {
		return nil, err
	}
	dr := d.Data
	c := dr.Counts
	g.para(fmt.Sprintf("%d installed products: %d Unapproved, %d Unreviewed, %d Approved, %d Ignored, %d Mandatory. "+
		"%d devices carry at least one Unapproved product.",
		c.InstalledProducts, c.Unapproved, c.Unreviewed, c.Approved, c.Ignored, c.Mandatory, c.UnapprovedDevices))
	g.coverage(dr.Coverage)

	sectionHeader(g.pdf, "Unapproved software present")
	if len(dr.UnapprovedPresent) == 0 {
		g.note("No device is currently reporting software marked Unapproved.")
	} else {
		rows := make([][]string, 0, len(dr.UnapprovedPresent))
		for _, u := range dr.UnapprovedPresent {
			hosts := make([]string, 0, governancePDFMaxDevices)
			for i, dev := range u.Devices {
				if i >= governancePDFMaxDevices {
					hosts = append(hosts, fmt.Sprintf("+%d more", len(u.Devices)-i))
					break
				}
				hosts = append(hosts, dev.Hostname)
			}
			by := "not recorded"
			if u.MarkedBy != nil {
				by = *u.MarkedBy
			} else if u.MarkedVia == softwaregov.SourceOperator {
				by = "operator"
			}
			rows = append(rows, []string{
				truncate(u.Name, 30), truncate(govPlatform(u.Product), 16), fmt.Sprintf("%d", u.DeviceCount),
				govDate(u.Since), truncate(by, 30), truncate(strings.Join(hosts, ", "), 40),
			})
		}
		g.table([]string{"Product", "Platform", "Devices", "Since", "Marked by", "Devices"},
			[]float64{40, 20, 14, 22, 36, 42}, rows)
	}

	sectionHeader(g.pdf, "Devices with the most Unapproved software")
	if len(dr.TopDevices) == 0 {
		g.note("None.")
	} else {
		rows := make([][]string, 0, len(dr.TopDevices))
		for _, t := range dr.TopDevices {
			seen := govDate(t.LastSeen)
			if t.Stale {
				seen += " (stale)"
			}
			rows = append(rows, []string{truncate(t.Hostname, 30), fmt.Sprintf("%d", t.UnapprovedProductCount),
				truncate(strings.Join(t.UnapprovedProductSample, ", "), 60), seen})
		}
		g.table([]string{"Device", "Unapproved", "Products", "Last reported"}, []float64{40, 20, 80, 34}, rows)
	}

	sectionHeader(g.pdf, "Trend, last 26 weeks")
	trendRows := make([][]string, 0, len(dr.Trend))
	for _, p := range dr.Trend {
		if !p.Recorded {
			trendRows = append(trendRows, []string{p.WeekStart, "not recorded", "not recorded", ""})
			continue
		}
		label := ""
		if p.Live {
			label = "this week so far"
		}
		trendRows = append(trendRows, []string{p.WeekStart, fmt.Sprintf("%d", *p.UnapprovedProducts),
			fmt.Sprintf("%d", *p.UnreviewedProducts), label})
	}
	g.table([]string{"Week starting", "Unapproved", "Unreviewed", ""}, []float64{40, 40, 40, 54}, trendRows)
	g.note("Weeks are recorded from when this report was first available. An unrecorded week is unknown, not zero.")

	sectionHeader(g.pdf, fmt.Sprintf("Unapproved and Unreviewed products (%d)", dr.ProductsTotal))
	if len(dr.Products) == 0 {
		g.note("Every installed product has an approval decision.")
	} else {
		rows := make([][]string, 0, len(dr.Products))
		for i, p := range dr.Products {
			if i >= governancePDFMaxRows {
				break
			}
			rows = append(rows, []string{truncate(p.Name, 34), p.ApprovalState, truncate(govPlatform(p.Product), 18),
				fmt.Sprintf("%d", p.DeviceCount), truncate(govIdentifier(p.Product), 40)})
		}
		g.table([]string{"Product", "State", "Platform", "Devices", "Identifier"}, []float64{46, 22, 26, 16, 64}, rows)
		if dr.ProductsTotal > len(rows) {
			g.note(fmt.Sprintf("%d further products are in the CSV export.", dr.ProductsTotal-len(rows)))
		}
	}
	return g.closer(title, d.GeneratedAt)
}

// RenderApprovedSoftwarePDF renders the Approved Software List for
// staff/admin use. Header carries the internal header.png mark, unchanged.
func RenderApprovedSoftwarePDF(d ApprovedSoftwareReport) ([]byte, error) {
	return renderApprovedSoftwarePDF(d, AudienceStaff)
}

// RenderApprovedSoftwarePDFCustomer renders the same Approved Software List
// for a customer's own portal download (PAT-2264). The only difference from
// RenderApprovedSoftwarePDF is the header: no "Staff report" wording and the
// current in-app brand mark instead of the retired pixel-P baked into
// header.png. Every other section, colour, font and layout is shared.
func RenderApprovedSoftwarePDFCustomer(d ApprovedSoftwareReport) ([]byte, error) {
	return renderApprovedSoftwarePDF(d, AudienceCustomer)
}

func renderApprovedSoftwarePDF(d ApprovedSoftwareReport, audience ReportAudience) ([]byte, error) {
	const title = "Approved Software List"
	g, err := newGovernancePDF(title, d.Tenant, d.GeneratedAt, audience)
	if err != nil {
		return nil, err
	}
	list := d.Data
	g.para(fmt.Sprintf("%d approved products, with who approved each one and when. "+
		"Where the approval was made by the operator rather than in the portal, the date is when the decision was last updated.", list.Total))
	if len(list.Products) == 0 {
		g.note("No product has been approved yet.")
		return g.closer(title, d.GeneratedAt)
	}
	rows := make([][]string, 0, len(list.Products))
	for i, p := range list.Products {
		if i >= governancePDFMaxRows {
			break
		}
		by := "operator"
		if p.ApprovedBy != nil {
			by = *p.ApprovedBy
		}
		platform := p.Platform
		ident := p.Identifier
		if p.Type == softwaregov.TypeBrowserExtension {
			platform, ident = p.Browser+" extension", p.ExtensionID
		}
		rows = append(rows, []string{truncate(p.Name, 30), truncate(platform, 18), truncate(ident, 34),
			truncate(by, 30), govDate(p.ApprovedAt)})
	}
	g.table([]string{"Product", "Platform", "Identifier", "Approved by", "Approved"}, []float64{40, 22, 48, 40, 24}, rows)
	if list.Total > len(rows) {
		g.note(fmt.Sprintf("%d further products are in the CSV export.", list.Total-len(rows)))
	}
	return g.closer(title, d.GeneratedAt)
}
