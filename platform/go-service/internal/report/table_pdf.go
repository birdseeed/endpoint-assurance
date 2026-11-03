package report

// Generic table PDF (PAT-2405). The customer portal builds its CSV list
// exports itself from platform JSON; this renders the same rows as a branded
// PDF so the portal needs no PDF renderer of its own. The caller supplies
// the title, tenant name, column headers and cells; nothing here reads a
// database or decides what the table contains.
//
// The one rule the layout exists to keep: no cell text is ever cut. Cells
// wrap onto as many lines as they need, a token wider than its column is
// broken across lines rather than clipped, and a row taller than a page
// continues on the next page.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-pdf/fpdf"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TableFilter is one "label: value" line printed under the title, saying
// which selection the rows are for.
type TableFilter struct {
	Label string
	Value string
}

// TablePDF is everything RenderTablePDF prints.
type TablePDF struct {
	Title       string
	Tenant      string
	GeneratedAt time.Time
	Filters     []TableFilter
	Columns     []string
	// Rows holds one slice per row, each exactly len(Columns) long.
	Rows [][]string
	// TotalRows, when greater than len(Rows), is the size of the full list
	// the rows were cut from; the PDF then says it shows the first
	// len(Rows) of TotalRows and that the CSV holds the rest.
	TotalRows int
}

// A4 landscape geometry. Side margins are narrower than the portrait
// reports' 18mm: a list export can carry forty columns and needs the width.
const (
	tablePageW      = 297.0
	tablePageH      = 210.0
	tableSideMargin = 12.0
	tableContentW   = tablePageW - 2*tableSideMargin
	tableBottomY    = tablePageH - bottomMargin

	tableMinColW = 8.0  // floor on a column's natural width
	tableMaxColW = 80.0 // ceiling on a column's natural width, before fitting
	// tableHeaderMaxShare caps the repeated header row at this share of a
	// page, so a row always has room to make progress beneath it.
	tableHeaderMaxShare = 0.6
)

// Resource limits apply to every caller, before font/layout allocations. Raw byte
// limits also bound malformed UTF-8 expansion; logical breaks count all forms
// normalised by tableText. Oversized exports are rejected, never truncated.
const (
	tableMaxTextBytes   = 32 << 10
	tableMaxInputBytes  = 8 << 20
	tableMaxTextLines   = 2048
	tableMaxPages       = 512
	tableMaxLayoutLines = 500000
)

var ErrTablePDFLimit = errors.New("table pdf exceeds rendering budget")
var ErrTablePDFBusy = errors.New("table pdf renderer busy")
var tablePDFSlots = make(chan struct{}, 2)

// ValidateTablePDF checks cheap input budgets without allocating normalised text.
func ValidateTablePDF(d TablePDF) error { return validateTablePDF(context.Background(), d) }

func validateTablePDF(ctx context.Context, d TablePDF) error {
	if len(d.Columns) == 0 || len(d.Columns) > 40 || len(d.Rows) > 10000 || len(d.Filters) > 20 {
		return fmt.Errorf("%w: table dimensions", ErrTablePDFLimit)
	}
	total := 0
	check := func(s string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(s) > tableMaxTextBytes || len(s) > tableMaxInputBytes-total {
			return ErrTablePDFLimit
		}
		total += len(s)
		lines := 1
		previousCR := false
		for _, r := range s {
			if r == '\r' || r == '\u2028' || r == '\u2029' || r == '\n' && !previousCR {
				lines++
			}
			previousCR = r == '\r'
			if lines > tableMaxTextLines {
				return ErrTablePDFLimit
			}
		}
		return nil
	}
	for _, s := range []string{d.Title, d.Tenant} {
		if err := check(s); err != nil {
			return err
		}
	}
	for _, f := range d.Filters {
		for _, s := range []string{f.Label, f.Value} {
			if err := check(s); err != nil {
				return err
			}
		}
	}
	for _, c := range d.Columns {
		if err := check(c); err != nil {
			return err
		}
		if utf8.RuneCountInString(c) > 120 {
			return fmt.Errorf("%w: column header", ErrTablePDFLimit)
		}
	}
	for i, row := range d.Rows {
		if len(row) != len(d.Columns) {
			return fmt.Errorf("table pdf: row %d has %d cells, want %d", i, len(row), len(d.Columns))
		}
		for _, cell := range row {
			if err := check(cell); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

// FetchTenantName returns the tenant's display name, the same lookup the
// report fetchers run. ErrTenantNotFound when the id does not resolve.
func FetchTenantName(ctx context.Context, pool *pgxpool.Pool, tenantID string) (string, error) {
	var name string
	if err := pool.QueryRow(ctx, `SELECT name FROM tenants WHERE id = $1::uuid`, tenantID).Scan(&name); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrTenantNotFound
		}
		return "", fmt.Errorf("tenant name: %w", err)
	}
	return name, nil
}

// RenderTablePDF renders d as an A4 landscape customer PDF: the customer
// header, title, tenant, generated time, filters, row count, then the table
// with its header row repeated on every page.
func RenderTablePDF(d TablePDF) ([]byte, error) {
	return RenderTablePDFContext(context.Background(), d)
}

// RenderTablePDFContext observes cancellation and admits at most two renders
// per process. Admission never queues work or holds request data waiting for a slot.
func RenderTablePDFContext(ctx context.Context, d TablePDF) ([]byte, error) {
	if err := validateTablePDF(ctx, d); err != nil {
		return nil, err
	}
	select {
	case tablePDFSlots <- struct{}{}:
		defer func() { <-tablePDFSlots }()
	default:
		return nil, ErrTablePDFBusy
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	title := tableLine(d.Title)
	pdf := fpdf.New("L", "mm", "A4", "")
	pdf.SetMargins(tableSideMargin, topMargin, tableSideMargin)
	// Page breaks are decided row by row below, so a row is never split by
	// fpdf part-way through a cell.
	pdf.SetAutoPageBreak(false, bottomMargin)
	pdf.SetTitle("Patched: "+title, true)
	pdf.SetAuthor("patched.im", true)
	pdf.SetCreator("patched-api report renderer", true)
	registerReportFont(pdf)
	pdf.SetFooterFunc(func() {
		// Core font on purpose: see registerReportFont on why the {nb}
		// page-total alias cannot go through the UTF-8 font.
		pdf.SetY(-10)
		pdf.SetFont("Helvetica", "", 8)
		setTextColour(pdf, colourMuted)
		pdf.CellFormat(0, 6, fmt.Sprintf("Page %d of {nb}", pdf.PageNo()), "", 0, "C", false, 0, "")
	})
	pdf.AliasNbPages("")
	pdf.AddPage()

	t := newTableLayoutContext(ctx, pdf, d)
	if !t.stopped() {
		t.renderHeading(title)
	}
	if !t.stopped() {
		t.renderTable()
	}
	if t.err != nil {
		return nil, t.err
	}

	if err := pdf.Error(); err != nil {
		return nil, fmt.Errorf("render table pdf: %w", err)
	}
	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("write table pdf: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// --- Text safety -------------------------------------------------------------

// tableText makes arbitrary input safe for fpdf's UTF-8 text path, which
// assumes well-formed UTF-8 inside the Basic Multilingual Plane: its UTF-16
// conversion reads continuation bytes without bounds checks and treats a
// four-byte sequence as three. Malformed bytes and characters above U+FFFF
// (emoji, for one; the report font has no glyph for them either) become
// U+FFFD, so a character is visibly replaced rather than dropped. Line
// breaks are kept as "\n"; tabs and other control characters become spaces.
func tableText(s string) string {
	plain := true
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 && c != '\n' || c >= 0x7f {
			plain = false
			break
		}
	}
	if plain {
		return s
	}
	s = strings.ToValidUTF8(s, "�")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n':
			return r
		case r == '\r', r == ' ', r == ' ':
			return '\n'
		case r > 0xFFFF:
			return '�'
		case unicode.IsControl(r):
			return ' '
		}
		return r
	}, s)
}

// tableLine is tableText for a value printed on one logical line.
func tableLine(s string) string {
	return strings.TrimSpace(strings.ReplaceAll(tableText(s), "\n", " "))
}

// --- Measuring and wrapping --------------------------------------------------

// tableFont measures and wraps text in one style and size of the report
// font. Rune widths are cached: a 10,000-row export measures hundreds of
// thousands of cells.
type tableFont struct {
	pdf   *fpdf.Fpdf
	style string
	size  float64
	lineH float64
	w     []float32
}

func newTableFont(pdf *fpdf.Fpdf, style string, size float64) *tableFont {
	f := &tableFont{pdf: pdf, style: style, size: size, lineH: size * 0.3528 * 1.3, w: make([]float32, 0x10000)}
	for i := range f.w {
		f.w[i] = -1
	}
	return f
}

func (f *tableFont) use() { f.pdf.SetFont(reportFont, f.style, f.size) }

func (f *tableFont) runeWidth(r rune) float64 {
	if r < 0 || r > 0xFFFF {
		r = '�'
	}
	if f.w[r] < 0 {
		f.use()
		f.w[r] = float32(f.pdf.GetStringWidth(string(r)))
	}
	return float64(f.w[r])
}

// width is the width of s on one line, giving up once it passes limit.
func (f *tableFont) width(s string, limit float64) float64 {
	w := 0.0
	for _, r := range s {
		w += f.runeWidth(r)
		if w > limit {
			break
		}
	}
	return w
}

// wrap breaks text into lines no wider than avail. It breaks at spaces where
// it can and inside a token where it must, and never drops a visible
// character: only the whitespace at a break is consumed.
func (f *tableFont) wrap(text string, avail float64) []string {
	if !strings.Contains(text, "\n") && f.width(text, avail) <= avail {
		return []string{text}
	}
	var out []string
	for _, para := range strings.Split(text, "\n") {
		n := len(out)
		out = f.wrapParagraph(out, para, avail)
		if len(out) == n {
			out = append(out, "")
		}
	}
	return out
}

func (f *tableFont) wrapParagraph(out []string, para string, avail float64) []string {
	runes := []rune(para)
	emit := func(from, to int) {
		if line := strings.TrimRightFunc(string(runes[from:to]), unicode.IsSpace); line != "" {
			out = append(out, line)
		}
	}
	start, lastSpace, w := 0, -1, 0.0
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if unicode.IsSpace(r) {
			lastSpace = i
		}
		rw := f.runeWidth(r)
		if w+rw > avail && i > start {
			if lastSpace > start {
				emit(start, lastSpace)
				start = lastSpace + 1
			} else {
				emit(start, i) // no space on this line: break inside the token
				start = i
			}
			for start < len(runes) && unicode.IsSpace(runes[start]) {
				start++
			}
			i, lastSpace, w = start-1, -1, 0
			continue
		}
		w += rw
	}
	if start < len(runes) {
		emit(start, len(runes))
	}
	return out
}

// fitTableColumnWidths turns natural column widths into widths that sum to
// avail. With room to spare every column grows in proportion. Without, the
// columns that already fit their fair share keep their width and only the
// wider ones give way, so one long free-text column does not squeeze a
// two-character one.
func fitTableColumnWidths(natural []float64, avail float64) []float64 {
	out := make([]float64, len(natural))
	sum := 0.0
	for i, w := range natural {
		out[i] = math.Max(w, 0.1)
		sum += out[i]
	}
	if sum <= avail {
		for i := range out {
			out[i] *= avail / sum
		}
		return out
	}
	order := make([]int, len(out))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return out[order[a]] < out[order[b]] })
	remaining := avail
	for k, i := range order {
		if out[i] <= remaining/float64(len(order)-k) {
			remaining -= out[i]
			continue
		}
		rest := 0.0
		for _, j := range order[k:] {
			rest += out[j]
		}
		for _, j := range order[k:] {
			out[j] *= remaining / rest
		}
		break
	}
	return out
}

// --- Layout ------------------------------------------------------------------

type tableLayout struct {
	ctx         context.Context
	err         error
	layoutLines int
	pdf         *fpdf.Fpdf
	d           TablePDF
	body        *tableFont
	head        *tableFont
	pad         float64 // horizontal padding inside a cell
	vpad        float64 // vertical padding above and below a row's text
	widths      []float64
	columns     [][]string // wrapped header lines per column
	headH       float64
}

// tableFontSize picks the body size from the column count: the more columns,
// the smaller the type, down to a size that still fits forty.
func tableFontSize(columns int) float64 {
	switch {
	case columns <= 6:
		return 8
	case columns <= 10:
		return 7.5
	case columns <= 14:
		return 7
	case columns <= 20:
		return 6
	case columns <= 28:
		return 5
	}
	return 4
}

func newTableLayout(pdf *fpdf.Fpdf, d TablePDF) *tableLayout {
	return newTableLayoutContext(context.Background(), pdf, d)
}

func newTableLayoutContext(ctx context.Context, pdf *fpdf.Fpdf, d TablePDF) *tableLayout {
	size := tableFontSize(len(d.Columns))
	t := &tableLayout{ctx: ctx, pdf: pdf, d: d,
		body: newTableFont(pdf, "", size), head: newTableFont(pdf, "B", size),
		pad: 1.0, vpad: 0.7}
	if len(d.Columns) > 14 {
		t.pad, t.vpad = 0.6, 0.5
	}

	// Natural width per column: its widest cell or header on one line,
	// bounded, and never narrower than the header's longest word where that
	// is reasonable.
	natural := make([]float64, len(d.Columns))
	headers := make([]string, len(d.Columns))
	for c, name := range d.Columns {
		headers[c] = tableLine(name)
		longestWord := 0.0
		for _, word := range strings.Fields(headers[c]) {
			longestWord = math.Max(longestWord, t.head.width(word, tableMaxColW))
		}
		natural[c] = math.Max(math.Min(longestWord, tableMaxColW/2), t.head.width(headers[c], tableMaxColW))
	}
	limit := tableMaxColW - 2*t.pad
	for _, row := range d.Rows {
		if t.stopped() {
			return t
		}
		for c, cell := range row {
			if natural[c] >= limit {
				continue
			}
			for _, line := range strings.Split(tableText(cell), "\n") {
				natural[c] = math.Max(natural[c], t.body.width(line, limit))
			}
		}
	}
	for c := range natural {
		natural[c] = math.Min(math.Max(natural[c]+2*t.pad, tableMinColW), tableMaxColW)
	}
	t.widths = fitTableColumnWidths(natural, tableContentW)

	// The header row is wrapped once and repeated on every page. Its height
	// is capped so rows always have room beneath it; a header past the cap
	// (only a pathologically long column name) is shortened with an
	// ellipsis, the one place this renderer ever shortens text.
	maxLines := int((tableHeaderMaxShare*(tableBottomY-topMargin) - 2*t.vpad) / t.head.lineH)
	t.columns = make([][]string, len(headers))
	most := 1
	for c, h := range headers {
		lines := t.head.wrap(h, t.widths[c]-2*t.pad)
		if len(lines) > maxLines {
			lines = lines[:maxLines]
			last := []rune(lines[maxLines-1])
			if len(last) > 1 {
				last = last[:len(last)-1]
			}
			lines[maxLines-1] = string(last) + "…"
		}
		t.columns[c] = lines
		most = max(most, len(lines))
	}
	t.headH = float64(most)*t.head.lineH + 2*t.vpad
	return t
}

// All page creation after the first page shares the same hard ceiling.
func (t *tableLayout) stopped() bool {
	if t.err == nil {
		t.err = t.ctx.Err()
	}
	return t.err != nil || t.pdf.Error() != nil
}
func (t *tableLayout) addPage() bool {
	if t.stopped() {
		return false
	}
	if t.pdf.PageNo() >= tableMaxPages {
		t.err = ErrTablePDFLimit
		return false
	}
	t.pdf.AddPage()
	t.pdf.SetY(topMargin)
	return !t.stopped()
}
func (t *tableLayout) accountLines(n int) bool {
	if t.stopped() {
		return false
	}
	if n > tableMaxLayoutLines-t.layoutLines {
		t.err = ErrTablePDFLimit
		return false
	}
	t.layoutLines += n
	return true
}
func (t *tableLayout) ensure(need float64) bool {
	if t.stopped() {
		return false
	}
	if t.pdf.GetY()+need > tableBottomY {
		return t.addPage()
	}
	return true
}

// paragraph prints text across the content width in the current font,
// wrapped, starting a new page if it runs out of room.
func (t *tableLayout) paragraph(f *tableFont, text, align string) {
	f.use()
	lines := f.wrap(text, tableContentW-2)
	if !t.accountLines(len(lines)) {
		return
	}
	for _, line := range lines {
		if !t.ensure(f.lineH) {
			return
		}
		f.use()
		t.pdf.SetX(tableSideMargin)
		t.pdf.CellFormat(tableContentW, f.lineH, line, "", 1, align, false, 0, "")
	}
}

func (t *tableLayout) renderHeading(title string) {
	pdf := t.pdf
	pdf.SetY(drawCustomerHeaderMarkOn(pdf, 40, tablePageW))
	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 5, "Endpoint Assurance  |  Audit Evidence", "", 1, "C", false, 0, "")
	pdf.Ln(1)
	hruleBetween(pdf, 0.6, tableSideMargin, tableSideMargin+tableContentW)

	pdf.Ln(2)
	setTextColour(pdf, colourBodyText)
	t.paragraph(newTableFont(pdf, "B", 16), title, "C")
	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 5, "Prepared for", "", 1, "C", false, 0, "")
	setTextColour(pdf, colourBodyText)
	t.paragraph(newTableFont(pdf, "B", 12), fallback(tableLine(t.d.Tenant)), "C")
	pdf.SetFont(reportFont, "", 9)
	pdf.CellFormat(0, 5, "Generated "+t.d.GeneratedAt.UTC().Format("02 Jan 2006 15:04")+" UTC  |  Classification: Confidential",
		"", 1, "C", false, 0, "")
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 5, "Prepared by Patched.im Ltd  |  patched.im", "", 1, "C", false, 0, "")
	pdf.Ln(1.5)
	hruleBetween(pdf, 0.4, tableSideMargin, tableSideMargin+tableContentW)
	pdf.Ln(2)

	regular, bold := newTableFont(pdf, "", 9), newTableFont(pdf, "B", 9)
	setTextColour(pdf, colourBodyText)
	if len(t.d.Filters) > 0 {
		t.paragraph(bold, "Filters", "L")
		for _, f := range t.d.Filters {
			if t.stopped() {
				return
			}
			t.paragraph(regular, tableLine(f.Label)+": "+tableLine(f.Value), "L")
		}
		pdf.Ln(1.5)
	}
	rows := len(t.d.Rows)
	switch {
	case t.d.TotalRows > rows:
		t.paragraph(bold, fmt.Sprintf("This PDF shows the first %d of %d rows. The CSV export holds the full list.", rows, t.d.TotalRows), "L")
	case rows == 1:
		t.paragraph(bold, "1 row", "L")
	default:
		t.paragraph(bold, fmt.Sprintf("%d rows", rows), "L")
	}
	pdf.Ln(1.5)
}

// headerRow draws the column header band at the current position.
func (t *tableLayout) headerRow() {
	pdf := t.pdf
	y := pdf.GetY()
	t.head.use()
	pdf.SetCellMargin(t.pad)
	setTextColour(pdf, colourBodyText)
	setFillColour(pdf, colourTableHdr)
	pdf.Rect(tableSideMargin, y, tableContentW, t.headH, "F")
	x := tableSideMargin
	for c, lines := range t.columns {
		for i, line := range lines {
			pdf.SetXY(x, y+t.vpad+float64(i)*t.head.lineH)
			pdf.CellFormat(t.widths[c], t.head.lineH, line, "", 0, "L", false, 0, "")
		}
		x += t.widths[c]
	}
	pdf.SetY(y + t.headH)
}

// nextPage starts a page and repeats the header row at its top.
func (t *tableLayout) nextPage() bool {
	if !t.addPage() {
		return false
	}
	t.headerRow()
	return true
}

func (t *tableLayout) renderTable() {
	pdf := t.pdf
	// Keep the header row with at least one line of the first row.
	if pdf.GetY()+t.headH+t.body.lineH+2*t.vpad > tableBottomY {
		if !t.nextPage() {
			return
		}
	} else {
		t.headerRow()
	}

	if len(t.d.Rows) == 0 {
		pdf.Ln(2)
		pdf.SetFont(reportFont, "I", 9)
		setTextColour(pdf, colourMuted)
		pdf.SetX(tableSideMargin)
		pdf.CellFormat(tableContentW, 5, "No rows for this selection.", "", 1, "L", false, 0, "")
		return
	}

	// The most a row can occupy on a page that starts with the header row.
	pageBody := tableBottomY - topMargin - t.headH
	cells := make([][]string, len(t.d.Columns))
	for r, row := range t.d.Rows {
		if t.stopped() {
			return
		}
		t.body.use()
		lines := 1
		for c, cell := range row {
			cells[c] = t.body.wrap(tableText(cell), t.widths[c]-2*t.pad)
			if !t.accountLines(len(cells[c])) {
				return
			}
			lines = max(lines, len(cells[c]))
		}
		rowH := float64(lines)*t.body.lineH + 2*t.vpad
		// A row never splits across pages unless it is taller than a page.
		if pdf.GetY()+rowH > tableBottomY && rowH <= pageBody {
			if !t.nextPage() {
				return
			}
		}
		for from := 0; from < lines; {
			room := int((tableBottomY-pdf.GetY()-2*t.vpad)/t.body.lineH + 1e-6)
			if room < 1 {
				if !t.nextPage() {
					return
				}
				room = max(1, int((tableBottomY-pdf.GetY()-2*t.vpad)/t.body.lineH+1e-6))
			}
			n := min(room, lines-from)
			t.rowSlice(cells, from, from+n, r%2 == 1)
			from += n
		}
	}
}

// rowSlice draws lines [from, to) of one row's wrapped cells as a band at
// the current position: the whole row, or one page's worth of a row taller
// than a page.
func (t *tableLayout) rowSlice(cells [][]string, from, to int, alt bool) {
	pdf := t.pdf
	y := pdf.GetY()
	h := float64(to-from)*t.body.lineH + 2*t.vpad
	t.body.use()
	pdf.SetCellMargin(t.pad)
	setTextColour(pdf, colourBodyText)
	if alt {
		setFillColour(pdf, colourRowAlt)
		pdf.Rect(tableSideMargin, y, tableContentW, h, "F")
	}
	x := tableSideMargin
	for c, lines := range cells {
		for i := from; i < to && i < len(lines); i++ {
			if lines[i] != "" {
				pdf.SetXY(x, y+t.vpad+float64(i-from)*t.body.lineH)
				pdf.CellFormat(t.widths[c], t.body.lineH, lines[i], "", 0, "L", false, 0, "")
			}
		}
		x += t.widths[c]
	}
	pdf.SetY(y + h)
}
