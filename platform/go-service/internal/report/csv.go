package report

// PAT-2405: CSV renderings of the customer catalogue reports. Each CSV is
// built from the same fetched data model as the PDF of the same generation,
// so the two files describe one moment.
//
// Conventions shared by every report CSV:
//   - UTF-8, no BOM, encoding/csv quoting, "\n" line endings (the same writer
//     the existing portal CSV exports use);
//   - the first row is a header, and a report with no rows is that header alone;
//   - a leading generated_at column, then (for reports with more than one
//     table) a section column naming the table a row belongs to, then the
//     union of the tables' columns, left empty where a section has no such
//     column;
//   - every cell, the header included, passes through CSVSafe.

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// CSVSafe neutralises a cell a spreadsheet would read as a formula: one that
// starts with =, +, -, @, tab or carriage return gets a leading single quote.
// This is the one definition; handlers.csvSafe delegates to it.
func CSVSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// csvRow is one row keyed by column name. A column a row does not set is empty.
type csvRow map[string]string

// writeReportCSV renders generated_at, an optional section column and the
// given columns. sectioned reports carry the section name in row["section"].
func writeReportCSV(generatedAt time.Time, sectioned bool, columns []string, rows []csvRow) ([]byte, error) {
	header := []string{"generated_at"}
	if sectioned {
		header = append(header, "section")
	}
	header = append(header, columns...)
	generated := csvTime(generatedAt)

	records := make([][]string, 0, len(rows))
	for _, r := range rows {
		cells := make([]string, 0, len(header))
		cells = append(cells, generated)
		if sectioned {
			cells = append(cells, r["section"])
		}
		for _, c := range columns {
			cells = append(cells, r[c])
		}
		records = append(records, cells)
	}
	return writeCSVTable(header, records)
}

// writeCSVTable writes a header and records with every cell, the header
// included, passed through CSVSafe.
func writeCSVTable(header []string, records [][]string) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	write := func(cells []string) error {
		safe := make([]string, len(cells))
		for i, c := range cells {
			safe[i] = CSVSafe(c)
		}
		return w.Write(safe)
	}
	if err := write(header); err != nil {
		return nil, err
	}
	for _, r := range records {
		if err := write(r); err != nil {
			return nil, err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("write report csv: %w", err)
	}
	return buf.Bytes(), nil
}

func csvTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func csvTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return csvTime(*t)
}

func csvInt(n int) string { return strconv.Itoa(n) }

// csvCount renders a count whose data model uses a negative sentinel for
// "unknown" (local-admin AdminCount and the median days since last patch are
// -1 when no signal was collected). Unknown is an empty cell, never a number:
// the PDF says "unknown" there, and a -1 would read as a figure.
func csvCount(n int) string {
	if n < 0 {
		return ""
	}
	return strconv.Itoa(n)
}

func csvIntPtr(n *int) string {
	if n == nil {
		return ""
	}
	return strconv.Itoa(*n)
}

func csvFloat(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

func csvFloatPtr(f *float64) string {
	if f == nil {
		return ""
	}
	return csvFloat(*f)
}

func csvStrPtr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func csvBool(b bool) string { return strconv.FormatBool(b) }
