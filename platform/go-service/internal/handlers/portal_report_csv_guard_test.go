package handlers

import (
	"context"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/report"
)

// PAT-2405: the CSV half of TestPortalReportRenderersMatchCustomerCatalogue.
// portalReportRenderers is the single registry for both files of a customer
// report: an entry renders the PDF and the CSV from one fetch, and hasCSV is
// set only when the constructor was given a CSV renderer. A catalogue type
// added with a PDF renderer and no CSV renderer fails here.
func TestPortalReportCSVRenderersCoverCustomerCatalogue(t *testing.T) {
	for _, def := range report.PortalReportCatalogue() {
		entry, found := portalReportRenderers[def.Type]
		if !found {
			t.Errorf("customer-facing report %q has no renderer", def.Type)
			continue
		}
		if entry.run == nil {
			t.Errorf("customer-facing report %q has no run function", def.Type)
		}
		if !entry.hasCSV {
			t.Errorf("customer-facing report %q has a PDF renderer but no CSV renderer", def.Type)
		}
	}
}

// TestPortalReportRendererWithoutCSVIsVisibleToTheGuard keeps the guard above
// honest: an entry built without a CSV renderer must read as having none,
// so omitting the argument cannot pass.
func TestPortalReportRendererWithoutCSVIsVisibleToTheGuard(t *testing.T) {
	fetch := func(context.Context, *pgxpool.Pool, string) (int, error) { return 1, nil }
	pdf := func(int) ([]byte, error) { return []byte("%PDF-"), nil }
	csv := func(int) ([]byte, error) { return []byte("a\n"), nil }

	if newPortalReportRenderer("x", "x", fetch, pdf, nil).hasCSV {
		t.Fatal("a renderer built with a nil CSV renderer reports hasCSV")
	}
	with := newPortalReportRenderer("x", "x", fetch, pdf, csv)
	if !with.hasCSV {
		t.Fatal("a renderer built with a CSV renderer does not report hasCSV")
	}
	out, err := with.run(context.Background(), nil, "t", slog.Default())
	if err != nil || string(out.pdf) != "%PDF-" || string(out.csv) != "a\n" {
		t.Fatalf("run = %q %q %v, want both files from one fetch", out.pdf, out.csv, err)
	}
}
