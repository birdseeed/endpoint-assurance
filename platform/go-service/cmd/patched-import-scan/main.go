// patched-import-scan: stateless one-shot CVE scan from an Intune app-inventory
// export. Reads CPE mappings and the CVE feed from the database (DATABASE_URL),
// parses the app inventory from -input (CSV or JSON), calls the shared Match
// engine per device, and writes a Free CVE Assessment PDF to -output (or stdout).
//
// No DB writes — every invocation is idempotent.
//
// Usage:
//
//	patched-import-scan -tenant "Acme Corp" -input apps.csv > report.pdf
//	patched-import-scan -tenant "Acme Corp" -input apps.json -format json -output report.pdf
//
// Input CSV (header row required):
//
//	deviceName,appName,appVersion
//	alice-mbp,Google Chrome,120.0.6099.130
//
// Intune "Device apps" exports use different column names; remap with a
// spreadsheet tool or pass -format json with pre-processed data.
//
// Input JSON:
//
//	[{"deviceName":"alice-mbp","appName":"Google Chrome","appVersion":"120.0.6099.130"}]
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"patched.im/api/internal/csvparse"
	"patched.im/api/internal/cvematch"
	"patched.im/api/internal/cvescan"
	"patched.im/api/internal/db"
	"patched.im/api/internal/report"
)

func main() {
	tenant := flag.String("tenant", "", "tenant / organisation name for the report header (required)")
	input := flag.String("input", "-", "path to app inventory file, or - for stdin")
	format := flag.String("format", "auto", "input format: csv | json | auto (detect from extension or first byte)")
	output := flag.String("output", "-", "path to output PDF file, or - for stdout")
	flag.Parse()

	if *tenant == "" {
		fmt.Fprintln(os.Stderr, "error: -tenant is required")
		flag.Usage()
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Open the input source.
	var inputReader io.Reader
	detectedFormat := *format
	if *input == "-" {
		inputReader = os.Stdin
	} else {
		f, err := os.Open(*input)
		if err != nil {
			logger.Error("open input", "path", *input, "err", err)
			os.Exit(1)
		}
		defer f.Close()
		inputReader = f
		if detectedFormat == "auto" {
			if strings.HasSuffix(strings.ToLower(*input), ".json") {
				detectedFormat = "json"
			} else {
				detectedFormat = "csv"
			}
		}
	}

	// Parse the inventory.
	var apps []csvparse.App
	var parseErr error
	switch detectedFormat {
	case "json":
		apps, parseErr = csvparse.ParseJSON(inputReader)
	default:
		apps, parseErr = csvparse.ParseCSV(inputReader)
	}
	if parseErr != nil {
		logger.Error("parse input", "format", detectedFormat, "err", parseErr)
		os.Exit(1)
	}
	logger.Info("inventory parsed", "rows", len(apps))

	// Connect to DB to load CVE feed + mappings (read-only; no writes).
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		logger.Error("DATABASE_URL not set")
		os.Exit(1)
	}
	ctx := context.Background()
	pool, err := db.Connect(ctx, dbURL)
	if err != nil {
		logger.Error("db connect failed", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	mappings, err := cvescan.LoadMappings(ctx, pool)
	if err != nil {
		logger.Error("load mappings", "err", err)
		os.Exit(1)
	}
	feed, err := cvescan.LoadFeed(ctx, pool)
	if err != nil {
		logger.Error("load cve feed", "err", err)
		os.Exit(1)
	}
	logger.Info("feed loaded", "mappings", len(mappings), "cves", len(feed))

	// Group apps by device, run Match per device, collect findings.
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

	rpt := cvescan.BuildReport(deviceFindings, feed, *tenant, time.Now().UTC())
	logger.Info("report built",
		"cves", rpt.TotalCVEs,
		"confirmed", rpt.ConfirmedHits,
		"possible", rpt.UnverifiedHits)

	// Render PDF.
	pdfBytes, err := report.RenderFreeCVEPDF(rpt)
	if err != nil {
		logger.Error("render pdf", "err", err)
		os.Exit(1)
	}

	// Write output.
	var w io.Writer
	if *output == "-" {
		w = os.Stdout
	} else {
		outFile, err := os.Create(*output)
		if err != nil {
			logger.Error("create output", "path", *output, "err", err)
			os.Exit(1)
		}
		defer outFile.Close()
		w = outFile
	}
	if _, err := w.Write(pdfBytes); err != nil {
		logger.Error("write pdf", "err", err)
		os.Exit(1)
	}
	logger.Info("done", "bytes", len(pdfBytes))
}
