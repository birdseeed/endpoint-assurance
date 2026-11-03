package handlers

// PAT-2509: the version sprawl CSV tells a reader what a "latest released"
// figure came from and when it was checked, and never prints the machine name
// of the catalogue source.

import (
	"encoding/csv"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/lifecycle"
)

func sprawlStrPtr(s string) *string { return &s }

func sprawlCSVRows(t *testing.T, rep lifecycle.SprawlReport) (string, [][]string) {
	t.Helper()
	rec := httptest.NewRecorder()
	writeVersionSprawlCSV(rec, rep, sprawlFilter{})
	body := rec.Body.String()
	records, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("parse csv: %v\n%s", err, body)
	}
	return body, records
}

func TestVersionSprawlCSVCarriesSourceLabelAndCheckedDate(t *testing.T) {
	verified := time.Date(2026, 10, 1, 8, 30, 0, 0, time.UTC)
	fetched := time.Date(2026, 10, 4, 3, 0, 0, 0, time.UTC)
	rep := lifecycle.SprawlReport{
		GeneratedAt: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC),
		Products: []lifecycle.SprawlProduct{
			{
				ProductKey: "app:cat", Name: "CatApp", Platform: "macos", LatestReleased: sprawlStrPtr("2.0.0"),
				LatestReleasedSource: &lifecycle.SprawlSource{
					Name: lifecycle.SourceCuratedCatalogue, Label: "Patched reference list", CheckedAt: &verified,
				},
			},
			{
				ProductKey: "app:lc", Name: "LcApp", Platform: "macos", LatestReleased: sprawlStrPtr("3.0.0"),
				LatestReleasedSource: &lifecycle.SprawlSource{
					Name: lifecycle.SourceName, Slug: "lcapp", URL: "https://endoflife.date/lcapp",
					Label: "endoflife.date", CheckedAt: &fetched,
				},
			},
			{ProductKey: "app:none", Name: "NoRef", Platform: "macos"},
		},
	}

	body, records := sprawlCSVRows(t, rep)

	wantHeader := "product_key,name,platform,distinct_versions,oldest_version,newest_version,latest_released," +
		"latest_released_source,devices_more_than_one_major_behind,devices_not_comparable,cve_count_oldest_version," +
		"device_count,stale_device_count,generated_at,latest_released_checked_at"
	if got := strings.Join(records[0], ","); got != wantHeader {
		t.Errorf("csv header =\n  %s\nwant\n  %s", got, wantHeader)
	}

	if strings.Contains(body, "curated_catalogue") {
		t.Errorf("csv prints the machine source name curated_catalogue:\n%s", body)
	}

	col := map[string]int{}
	for i, h := range records[0] {
		col[h] = i
	}
	cat, lc, none := records[1], records[2], records[3]
	if cat[col["latest_released_source"]] != "Patched reference list" ||
		cat[col["latest_released_checked_at"]] != "2026-10-01T08:30:00Z" {
		t.Errorf("catalogue row source cells = %q / %q", cat[col["latest_released_source"]], cat[col["latest_released_checked_at"]])
	}
	if lc[col["latest_released_source"]] != "endoflife.date" ||
		lc[col["latest_released_checked_at"]] != "2026-10-04T03:00:00Z" {
		t.Errorf("lifecycle row source cells = %q / %q", lc[col["latest_released_source"]], lc[col["latest_released_checked_at"]])
	}
	if none[col["latest_released"]] != "" || none[col["latest_released_source"]] != "" ||
		none[col["latest_released_checked_at"]] != "" {
		t.Errorf("a row with no reference must leave every reference cell empty, got %q", none)
	}
	if _, dup := col["latest_released_source_label"]; dup {
		t.Errorf("csv repeats the source label in a second column; latest_released_source already holds it")
	}
}
