package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/csvparse"
	"patched.im/api/internal/cvematch"
	"patched.im/api/internal/cvescan"
	"patched.im/api/internal/report"
)

// ImportCVEScanHandler handles POST /admin/import-scan/cve.pdf.
//
// Accepts a multipart/form-data body with two fields:
//   - company: display name for the report header (required)
//   - apps:    CSV file — deviceName, appName, appVersion columns (required)
//
// Returns the PDF inline (Content-Disposition: attachment). No DB writes;
// every call is idempotent.
func ImportCVEScanHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			http.Error(w, "invalid multipart body", http.StatusBadRequest)
			return
		}

		company := strings.TrimSpace(r.FormValue("company"))
		if company == "" {
			http.Error(w, "company field is required", http.StatusBadRequest)
			return
		}

		f, _, err := r.FormFile("apps")
		if err != nil {
			http.Error(w, "apps file is required", http.StatusBadRequest)
			return
		}
		defer f.Close()

		apps, err := csvparse.ParseCSV(f)
		if err != nil {
			http.Error(w, "could not parse apps CSV: "+err.Error(), http.StatusUnprocessableEntity)
			return
		}
		if len(apps) == 0 {
			http.Error(w, "apps CSV has no usable rows", http.StatusUnprocessableEntity)
			return
		}

		ctx := r.Context()
		mappings, err := cvescan.LoadMappings(ctx, pool)
		if err != nil {
			http.Error(w, "internal error loading mappings", http.StatusInternalServerError)
			return
		}
		feed, err := cvescan.LoadFeed(ctx, pool)
		if err != nil {
			http.Error(w, "internal error loading feed", http.StatusInternalServerError)
			return
		}

		deviceApps := cvescan.GroupByDevice(apps)
		deviceFindings := map[string][]cvematch.Finding{}
		for device, scanned := range deviceApps {
			// The import carries no device OS (csvparse.App has none), so the
			// platform is unknown and nothing is filtered by platform (PAT-2107).
			findings := cvematch.Match(scanned, mappings, feed, "")
			if len(findings) > 0 {
				deviceFindings[device] = findings
			}
		}

		rpt := cvescan.BuildReport(deviceFindings, feed, company, time.Now().UTC())

		pdfBytes, err := report.RenderFreeCVEPDF(rpt)
		if err != nil {
			http.Error(w, "could not render PDF", http.StatusInternalServerError)
			return
		}

		stem := strings.ToLower(strings.ReplaceAll(company, " ", "-"))
		filename := fmt.Sprintf("cve-assessment-%s-%s.pdf", stem, rpt.GeneratedAt.Format("20060102"))
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(pdfBytes)))
		w.WriteHeader(http.StatusOK)
		w.Write(pdfBytes) //nolint:errcheck
	}
}
