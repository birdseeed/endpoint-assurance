package report

// PAT-2405: the generic table renderer behind POST
// /v1/portal/exports/table-pdf. The portal sends the rows of a CSV list
// export; the PDF must show exactly those rows, so the tests below read the
// text back out of the rendered PDF (extractReportPDFText) rather than only
// checking that something rendered.

import (
	"context"
	"errors"
	"fmt"
	"github.com/go-pdf/fpdf"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode"
)

var tablePDFGenerated = time.Date(2026, 10, 4, 21, 5, 0, 0, time.UTC)

func tablePDFText(t *testing.T, d TablePDF) (string, []byte) {
	t.Helper()
	pdf, err := RenderTablePDF(d)
	if err != nil {
		t.Fatalf("RenderTablePDF: %v", err)
	}
	if !strings.HasPrefix(string(pdf), "%PDF-") {
		t.Fatalf("output is not a PDF (first bytes: %q)", pdf[:8])
	}
	text, err := extractReportPDFText(pdf)
	if err != nil {
		t.Fatalf("extract text: %v", err)
	}
	return text, pdf
}

// tablePDFSquash drops all whitespace, so a value wrapped over several lines
// still compares equal to what was sent.
func tablePDFSquash(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

// tablePDFHasFooter looks for the page-number footer. It is drawn in a core
// (single-byte) font, which extractReportPDFText does not decode, so this
// reads the content streams directly.
func tablePDFHasFooter(t *testing.T, pdf []byte, footer string) bool {
	t.Helper()
	streams, err := reportPDFContentStreams(pdf)
	if err != nil {
		t.Fatalf("content streams: %v", err)
	}
	for _, s := range streams {
		if strings.Contains(string(s), "("+footer+")") {
			return true
		}
	}
	return false
}

var reTablePDFPage = regexp.MustCompile(`/Type\s*/Page[^s]`)

func tablePDFPages(pdf []byte) int { return len(reTablePDFPage.FindAll(pdf, -1)) }

func TestRenderTablePDF_SmallTableShowsEveryCell(t *testing.T) {
	d := TablePDF{
		Title:       "Devices",
		Tenant:      "Acme Table Co",
		GeneratedAt: tablePDFGenerated,
		Filters:     []TableFilter{{Label: "Platform", Value: "macOS"}, {Label: "Seen", Value: "Last 7 days"}},
		Columns:     []string{"Hostname", "Platform", "Serial", "Owner"},
		Rows: [][]string{
			{"mac-01", "macOS", "C02XK0AAJGH5", "alice@acme.example"},
			{"win-02", "Windows", "PF2ABCDE", "bob@acme.example"},
			{"mac-03", "macOS", "C02ZZ9BBJGH7", ""},
		},
	}
	text, pdf := tablePDFText(t, d)
	squashed := tablePDFSquash(text)
	want := []string{d.Title, d.Tenant, "04 Oct 2026 21:05 UTC", "Platform: macOS", "Seen: Last 7 days", "3 rows"}
	want = append(want, d.Columns...)
	for _, row := range d.Rows {
		want = append(want, row...)
	}
	for _, w := range want {
		if w != "" && !strings.Contains(squashed, tablePDFSquash(w)) {
			t.Errorf("rendered PDF text is missing %q", w)
		}
	}
	if !tablePDFHasFooter(t, pdf, "Page 1 of 1") {
		t.Errorf("footer does not say \"Page 1 of 1\"")
	}
	// A4 landscape: the page box is wider than it is tall.
	if !strings.Contains(string(pdf), "/MediaBox [0 0 841.89 595.28]") {
		t.Errorf("page is not A4 landscape")
	}
	if strings.Contains(squashed, "first3of") {
		t.Errorf("an untruncated table must not carry the truncation notice")
	}
}

func TestRenderTablePDF_NoFiltersRendersNoFilterLine(t *testing.T) {
	text, _ := tablePDFText(t, TablePDF{Title: "Findings", Tenant: "Acme", GeneratedAt: tablePDFGenerated,
		Columns: []string{"CVE"}, Rows: [][]string{{"CVE-2026-0001"}}})
	if strings.Contains(text, "Filters") {
		t.Errorf("no filters were sent but the PDF mentions filters: %q", text)
	}
	if !strings.Contains(tablePDFSquash(text), "1row") {
		t.Errorf("row count missing: %q", text)
	}
}

func TestRenderTablePDF_HeaderRepeatsOnEveryPage(t *testing.T) {
	d := TablePDF{Title: "Devices", Tenant: "Acme", GeneratedAt: tablePDFGenerated,
		Columns: []string{"ZQHOSTCOL", "ZQSERIALCOL", "ZQOWNERCOL"}}
	for i := 0; i < 2000; i++ {
		d.Rows = append(d.Rows, []string{fmt.Sprintf("host-%04d", i), fmt.Sprintf("serial-%04d", i), fmt.Sprintf("owner-%04d", i)})
	}
	text, pdf := tablePDFText(t, d)
	pages := tablePDFPages(pdf)
	if pages < 2 {
		t.Fatalf("2,000 rows rendered on %d page(s), want more than one", pages)
	}
	for _, col := range d.Columns {
		if got := strings.Count(text, col); got != pages {
			t.Errorf("column header %q appears %d times across %d pages, want once per page", col, got, pages)
		}
	}
	squashed := tablePDFSquash(text)
	for _, probe := range []string{"host-0000", "serial-0999", "owner-1999", "2000rows"} {
		if !strings.Contains(squashed, probe) {
			t.Errorf("rendered PDF text is missing %q", probe)
		}
	}
	for _, page := range []int{1, pages} {
		if want := fmt.Sprintf("Page %d of %d", page, pages); !tablePDFHasFooter(t, pdf, want) {
			t.Errorf("footer %q missing", want)
		}
	}
}

func TestRenderTablePDF_LongCellsAreNeverCut(t *testing.T) {
	var words []string
	for i := 0; i < 90; i++ {
		words = append(words, fmt.Sprintf("word%03d", i))
	}
	long := strings.Join(words, " ") // 90 words, 719 characters
	token := strings.Repeat("0123456789abcdefghij", 10)
	if len(long) < 500 || len(token) != 200 {
		t.Fatalf("fixture sizes: long=%d token=%d", len(long), len(token))
	}
	d := TablePDF{Title: "Findings", Tenant: "Acme", GeneratedAt: tablePDFGenerated,
		Columns: []string{"Name", "Description", "Path", "Count"},
		Rows: [][]string{
			{"alpha", long, token, "1"},
			{"beta", "short", "short", "2"},
		}}
	text, _ := tablePDFText(t, d)
	squashed := tablePDFSquash(text)
	if !strings.Contains(squashed, tablePDFSquash(long)) {
		t.Errorf("the long cell is not present in full")
	}
	if !strings.Contains(squashed, token) {
		t.Errorf("the 200-character unbreakable token is not present in full")
	}
	if strings.Contains(text, "…") {
		t.Errorf("rendered text carries an ellipsis: something was truncated")
	}
}

// A row taller than a page is the one case allowed to split; nothing in it
// may be dropped at the page boundary.
func TestRenderTablePDF_RowTallerThanAPageKeepsAllText(t *testing.T) {
	var words []string
	for i := 0; i < 3000; i++ {
		words = append(words, fmt.Sprintf("w%04d", i))
	}
	huge := strings.Join(words, " ")
	d := TablePDF{Title: "Findings", Tenant: "Acme", GeneratedAt: tablePDFGenerated,
		Columns: []string{"ZQKEY", "ZQTEXT"}, Rows: [][]string{{"k1", huge}, {"k2", "after"}}}
	text, pdf := tablePDFText(t, d)
	pages := tablePDFPages(pdf)
	if pages < 2 {
		t.Fatalf("expected the oversized row to run onto further pages, got %d", pages)
	}
	// The cell is interrupted by each page's footer and repeated header, so
	// check every word is present exactly once and in order rather than
	// looking for one unbroken run.
	at := 0
	for _, w := range words {
		if n := strings.Count(text, w); n != 1 {
			t.Fatalf("word %q appears %d times, want exactly once", w, n)
		}
		i := strings.Index(text[at:], w)
		if i < 0 {
			t.Fatalf("word %q is out of order", w)
		}
		at += i
	}
	if !strings.Contains(text, "after") || !strings.Contains(text, "k2") {
		t.Errorf("the row after the oversized one is missing")
	}
	if got := strings.Count(text, "ZQTEXT"); got != pages {
		t.Errorf("column header appears %d times across %d pages", got, pages)
	}
}

func TestRenderTablePDF_ZeroRows(t *testing.T) {
	text, _ := tablePDFText(t, TablePDF{Title: "Stale devices", Tenant: "Acme", GeneratedAt: tablePDFGenerated,
		Columns: []string{"Hostname", "Last seen"}, Rows: [][]string{}})
	if !strings.Contains(text, "No rows for this selection") {
		t.Errorf("zero rows must say so plainly; text: %q", text)
	}
	if !strings.Contains(text, "Stale devices") {
		t.Errorf("title missing on an empty table")
	}
}

func TestRenderTablePDF_TruncationNotice(t *testing.T) {
	d := TablePDF{Title: "Devices", Tenant: "Acme", GeneratedAt: tablePDFGenerated,
		Columns: []string{"Hostname"}, Rows: [][]string{{"a"}, {"b"}}, TotalRows: 12345}
	text, _ := tablePDFText(t, d)
	if !strings.Contains(text, "first 2 of 12345 rows") {
		t.Errorf("truncation notice missing \"first N of M\"; text: %q", text)
	}
	if !strings.Contains(text, "CSV") {
		t.Errorf("truncation notice must point at the CSV for the full list; text: %q", text)
	}
}

func TestRenderTablePDF_FortyColumnsStillRender(t *testing.T) {
	d := TablePDF{Title: "Software publishers", Tenant: "Acme", GeneratedAt: tablePDFGenerated}
	for c := 0; c < 40; c++ {
		d.Columns = append(d.Columns, fmt.Sprintf("Col%02d", c))
	}
	for r := 0; r < 30; r++ {
		row := make([]string, 40)
		for c := range row {
			row[c] = fmt.Sprintf("r%02dc%02dvalue", r, c)
		}
		d.Rows = append(d.Rows, row)
	}
	text, _ := tablePDFText(t, d)
	squashed := tablePDFSquash(text)
	for _, probe := range []string{"Col00", "Col39", "r00c00value", "r29c39value", "r15c20value"} {
		if !strings.Contains(squashed, probe) {
			t.Errorf("40-column table is missing %q", probe)
		}
	}
}

// Arbitrary Unicode must never make the render fail or panic. fpdf's UTF-8
// writer only understands the Basic Multilingual Plane and assumes well-formed
// input, so the renderer has to make text safe before handing it over.
func TestRenderTablePDF_ArbitraryUnicodeNeverErrors(t *testing.T) {
	nasty := []string{
		"plain",
		"Zoë’s “MacBook” — naïve café ≤ ≥ • …",
		"日本語のテキスト 中文 한국어",
		"مرحبا بالعالم עברית",
		"emoji 😀🚀 astral \U00010000 \U0010FFFF",
		"bad utf8 \xff\xfe\xf0\x9f trailing \xe2\x82",
		"controls \x00\x01\x1b[31m\ttab\r\nnewline\x7f",
		"combining e\u0301 zero\u200bwidth \ufeff bom \uffff \ufffe",
		"(parens) \\backslash\\ <angle> %percent",
		strings.Repeat("😀", 300),
		"",
	}
	d := TablePDF{Title: "Devices", Tenant: "Ünïcode 😀 Tenant \xff", GeneratedAt: tablePDFGenerated,
		Filters: []TableFilter{{Label: "Näme 😀", Value: "\xf0\x9f"}},
		Columns: []string{"A 😀", "B\xff", "C"}}
	for _, s := range nasty {
		d.Rows = append(d.Rows, []string{s, s, s})
	}
	text, _ := tablePDFText(t, d)
	squashed := tablePDFSquash(text)
	for _, probe := range []string{"Zoë’s“MacBook”—naïvecafé≤≥•…", "日本語のテキスト", "(parens)\\backslash\\<angle>%percent"} {
		if !strings.Contains(squashed, probe) {
			t.Errorf("Unicode text %q did not round-trip", probe)
		}
	}
}

func TestTableColumnWidthsFitThePrintableWidth(t *testing.T) {
	for _, natural := range [][]float64{
		{10, 20, 30},
		{400, 5, 5},
		{90, 90, 90, 90, 90, 90},
		{3},
	} {
		got := fitTableColumnWidths(natural, 273)
		sum := 0.0
		for i, w := range got {
			if w <= 0 {
				t.Errorf("natural %v: column %d got width %v", natural, i, w)
			}
			sum += w
		}
		if sum < 272.9 || sum > 273.1 {
			t.Errorf("natural %v: widths %v sum to %v, want the printable width 273", natural, got, sum)
		}
	}
	// A narrow column keeps its width when a wide neighbour has to give way.
	got := fitTableColumnWidths([]float64{400, 20, 20}, 273)
	if got[1] < 20 || got[2] < 20 {
		t.Errorf("narrow columns were squeezed to make room for a wide one: %v", got)
	}
}

func TestRenderTablePDF_ResourceBudget(t *testing.T) {
	d := TablePDF{Columns: []string{"value"}, Rows: [][]string{{strings.Repeat("x", (32<<10)+1)}}}
	if pdf, err := RenderTablePDF(d); err == nil || len(pdf) != 0 {
		t.Fatal("over-budget text must fail without a PDF")
	}
}

func TestRenderTablePDF_PreflightBudgets(t *testing.T) {
	valid := func() TablePDF {
		return TablePDF{Title: "Devices", Tenant: "Acme", Columns: []string{"Value"}, Rows: [][]string{{"ok"}}}
	}
	cases := map[string]func(*TablePDF){
		"title":        func(d *TablePDF) { d.Title = strings.Repeat("x", tableMaxTextBytes+1) },
		"tenant":       func(d *TablePDF) { d.Tenant = strings.Repeat("x", tableMaxTextBytes+1) },
		"header":       func(d *TablePDF) { d.Columns[0] = strings.Repeat("x", 121) },
		"filter label": func(d *TablePDF) { d.Filters = []TableFilter{{Label: strings.Repeat("x", tableMaxTextBytes+1)}} },
		"filter value": func(d *TablePDF) { d.Filters = []TableFilter{{Value: strings.Repeat("x", tableMaxTextBytes+1)}} },
		"aggregate": func(d *TablePDF) {
			d.Rows = make([][]string, 257)
			for i := range d.Rows {
				d.Rows[i] = []string{strings.Repeat("x", tableMaxTextBytes)}
			}
		},
		"shape": func(d *TablePDF) { d.Rows = make([][]string, 10001) },
	}
	for _, sep := range []string{"\n", "\r", "\r\n", "\u2028", "\u2029"} {
		sep := sep
		cases[fmt.Sprintf("break %q", sep)] = func(d *TablePDF) { d.Rows[0][0] = strings.Repeat(sep, tableMaxTextLines) }
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d := valid()
			mutate(&d)
			pdf, err := RenderTablePDF(d)
			if !errors.Is(err, ErrTablePDFLimit) || len(pdf) != 0 {
				t.Fatalf("want budget error and no PDF, got %v / %d", err, len(pdf))
			}
		})
	}
	// Invalid UTF-8 and a long token remain finite and retain existing replacement semantics.
	d := valid()
	d.Rows[0][0] = strings.Repeat("\xff", 100) + strings.Repeat("x", 18000)
	if _, err := RenderTablePDF(d); err != nil {
		t.Fatal(err)
	}
}

func TestRenderTablePDF_PageLimitStopsBothPaths(t *testing.T) {
	for _, heading := range []bool{true, false} {
		pdf := fpdf.New("L", "mm", "A4", "")
		for i := 0; i < tableMaxPages; i++ {
			pdf.AddPage()
		}
		layout := &tableLayout{ctx: context.Background(), pdf: pdf}
		pdf.SetY(tableBottomY)
		var ok bool
		if heading {
			ok = layout.ensure(1)
		} else {
			ok = layout.nextPage()
		}
		if ok || !errors.Is(layout.err, ErrTablePDFLimit) || pdf.PageNo() != tableMaxPages {
			t.Fatalf("page guard failed: %v %v %d", ok, layout.err, pdf.PageNo())
		}
	}
	d := TablePDF{Columns: []string{"Value"}, Rows: make([][]string, 30)}
	for i := range d.Rows {
		d.Rows[i] = []string{strings.Repeat("\n", 1000)}
	}
	if pdf, err := RenderTablePDF(d); !errors.Is(err, ErrTablePDFLimit) || len(pdf) != 0 {
		t.Fatalf("page exhaustion must return no partial PDF: %v / %d", err, len(pdf))
	}
}

func TestRenderTablePDF_CancellationAndAdmission(t *testing.T) {
	d := TablePDF{Columns: []string{"Value"}, Rows: [][]string{{"ok"}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if pdf, err := RenderTablePDFContext(ctx, d); !errors.Is(err, context.Canceled) || len(pdf) != 0 {
		t.Fatalf("canceled render: %v", err)
	}
	for i := 0; i < cap(tablePDFSlots); i++ {
		tablePDFSlots <- struct{}{}
	}
	pdf, err := RenderTablePDFContext(context.Background(), d)
	for i := 0; i < cap(tablePDFSlots); i++ {
		<-tablePDFSlots
	}
	if !errors.Is(err, ErrTablePDFBusy) || len(pdf) != 0 {
		t.Fatalf("occupied render slots: %v", err)
	}
	if _, err := RenderTablePDF(d); err != nil {
		t.Fatalf("slots not reusable: %v", err)
	}
	layout := &tableLayout{ctx: ctx, pdf: fpdf.New("L", "mm", "A4", "")}
	if layout.addPage() || !errors.Is(layout.err, context.Canceled) {
		t.Fatal("layout ignored cancellation")
	}
}
