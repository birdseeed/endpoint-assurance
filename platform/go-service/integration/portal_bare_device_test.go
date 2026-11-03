//go:build integration

package integration

// PAT-2538: one device that reports almost nothing must never take a tenant's
// report or list down.
//
// POST /v1/portal/reports {"report_type":"local-admin"} answered 500 for any
// tenant holding a device whose hostname is NULL, because the report scanned
// devices.hostname into a plain string. devices.hostname, serial, computer_name
// and os are all nullable, so the defect is a class: any query that scans a
// nullable devices column into a non-nullable Go value fails the same way for
// the tenant that owns such a row. This test is the guard for the class rather
// than the one query, so it walks the catalogue instead of naming types.
//
// This file covers the report half through the integration router: every type
// in the portal report catalogue, in every format it was generated in, plus the
// device roster export. The route half (every GET under /v1/portal, per-device
// routes for both devices) lives in cmd/patched-api and independently exercises
// the actual production router. TestPAT2539IntegrationRoutesMatchProduction
// guards current route parity for this package's hand-kept buildPublicRouter.
// See cmd/patched-api/portal_bare_device_pat2538_test.go.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// bareDeviceRequiredColumns is the set of devices columns the schema forces a
// writer to supply: NOT NULL with no default. It was determined from the
// migrations, not guessed: 0001_initial.sql declares devices.tenant_id NOT NULL
// REFERENCES tenants, and os NOT NULL, serial/hostname/computer_name/hw_uuid/
// os_version/etc nullable; 0039_nullable_os.sql then dropped NOT NULL on os;
// id, first_seen and last_seen carry defaults (gen_random_uuid(), now()), as do
// the later NOT NULL additions. seedBareDevice re-reads the set from
// information_schema and fails if it ever differs, so a migration that adds a
// required column breaks this test with a message rather than quietly making
// the "bare" device less bare.
var bareDeviceRequiredColumns = []string{"tenant_id"}

// seedBareDevice inserts a device carrying only the columns the schema
// requires, leaving every nullable column NULL.
func seedBareDevice(t *testing.T, tenantID string) string {
	t.Helper()
	ctx := t.Context()

	rows, err := env.pool.Query(ctx, `
		SELECT column_name FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'devices'
		  AND is_nullable = 'NO' AND column_default IS NULL
		  AND is_generated = 'NEVER' AND is_identity = 'NO'
		ORDER BY column_name`)
	if err != nil {
		t.Fatalf("read required devices columns: %v", err)
	}
	var required []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			rows.Close()
			t.Fatalf("scan required devices column: %v", err)
		}
		required = append(required, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("read required devices columns: %v", err)
	}
	if !reflect.DeepEqual(required, bareDeviceRequiredColumns) {
		t.Fatalf("devices requires columns %v but seedBareDevice supplies %v: supply the new required column and keep every nullable column NULL",
			required, bareDeviceRequiredColumns)
	}

	var id string
	if err := env.pool.QueryRow(ctx,
		`INSERT INTO devices (tenant_id) VALUES ($1::uuid) RETURNING id::text`, tenantID).Scan(&id); err != nil {
		t.Fatalf("seed bare device: %v", err)
	}

	// The device must really be bare: the columns the reports scan are NULL.
	var hostname, computerName, serial, osName *string
	if err := env.pool.QueryRow(ctx,
		`SELECT hostname, computer_name, serial, os FROM devices WHERE id = $1::uuid`, id,
	).Scan(&hostname, &computerName, &serial, &osName); err != nil {
		t.Fatalf("re-read bare device: %v", err)
	}
	if hostname != nil || computerName != nil || serial != nil || osName != nil {
		t.Fatalf("bare device is not bare: hostname=%v computer_name=%v serial=%v os=%v",
			hostname, computerName, serial, osName)
	}
	children, err := os.ReadFile("../testdata/bare-device-children.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(t.Context(), string(children), tenantID, id); err != nil {
		t.Fatalf("seed bare child rows: %v", err)
	}
	t.Log("bare device child rows: application, compliance signal, Homebrew formula/state, npm tooling entry/state")
	return id
}

// bareFailure is one request that answered 5xx.
type bareFailure struct {
	what   string
	status int
	body   string
}

func (f bareFailure) String() string {
	body := strings.TrimSpace(f.body)
	if len(body) > 300 {
		body = body[:300] + "..."
	}
	return fmt.Sprintf("%s = %d: %s", f.what, f.status, body)
}

// bareDo issues one portal request and records a failure when it answers 5xx.
func bareDo(t *testing.T, failures *[]bareFailure, what, method, path, token string, body io.Reader) (int, []byte) {
	t.Helper()
	resp := portalDo(t, method, path, token, body)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s: read body: %v", what, err)
	}
	if resp.StatusCode >= http.StatusInternalServerError {
		*failures = append(*failures, bareFailure{what: what, status: resp.StatusCode, body: string(raw)})
	}
	return resp.StatusCode, raw
}

func TestPortalSurvivesADeviceWithOnlyRequiredColumns(t *testing.T) {
	g := newGovTenant(t, "bare", "")
	govDevice(t, g.id, "normal-"+randomHex(3), "macOS", time.Now().UTC())
	seedBareDevice(t, g.id)

	var failures []bareFailure

	// (a) Every report type the portal catalogue offers an admin, in every
	// format the generated record says it holds. The catalogue is read from the
	// API, so a type added later is covered without anyone editing this test.
	types := pat2405PortalCatalogueTypes(t, g.adminToken)
	generated, downloads := 0, 0
	for _, reportType := range types {
		what := "POST /v1/portal/reports " + reportType
		body := fmt.Sprintf(`{"report_type":%q,"name":%q}`, reportType, "bare device "+reportType)
		status, raw := bareDo(t, &failures, what, http.MethodPost, "/v1/portal/reports", g.adminToken, strings.NewReader(body))
		if status != http.StatusCreated {
			continue
		}
		generated++
		var rec struct {
			ID      string   `json:"id"`
			Formats []string `json:"formats"`
		}
		if err := json.Unmarshal(raw, &rec); err != nil || rec.ID == "" {
			t.Fatalf("%s: decode created record: %v (%s)", what, err, raw)
		}
		if len(rec.Formats) == 0 {
			t.Errorf("%s: record %s offers no download format", what, rec.ID)
		}
		for _, format := range rec.Formats {
			downloads++
			bareDo(t, &failures, fmt.Sprintf("GET /v1/portal/reports/%s?format=%s (%s)", rec.ID, format, reportType),
				http.MethodGet, "/v1/portal/reports/"+rec.ID+"?format="+format, g.adminToken, nil)
		}
	}
	if len(types) == 0 {
		t.Fatal("empty portal report catalogue")
	}

	// (c) The device roster export. The portal builds the roster CSV itself
	// from GET /v1/portal/devices and posts the same cells to the table-pdf
	// renderer for the PDF, so the check is: the roster endpoint answers for a
	// tenant holding a bare device, and the PDF renderer accepts the cells a
	// bare device produces (a missing hostname arrives as an empty cell).
	status, raw := bareDo(t, &failures, "GET /v1/portal/devices", http.MethodGet, "/v1/portal/devices", g.adminToken, nil)
	if status == http.StatusOK {
		var roster struct {
			Devices []struct {
				Hostname  *string `json:"hostname"`
				Platform  *string `json:"platform"`
				OSVersion *string `json:"os_version"`
			} `json:"devices"`
		}
		if err := json.Unmarshal(raw, &roster); err != nil {
			t.Fatalf("decode roster: %v (%s)", err, raw)
		}
		if len(roster.Devices) != 2 {
			t.Errorf("roster holds %d devices, want 2 (one normal, one bare): %s", len(roster.Devices), raw)
		}
		cell := func(s *string) string {
			if s == nil {
				return ""
			}
			return *s
		}
		rows := make([][]string, 0, len(roster.Devices))
		for _, d := range roster.Devices {
			rows = append(rows, []string{cell(d.Hostname), cell(d.Platform), cell(d.OSVersion)})
		}
		pdfBody, err := json.Marshal(map[string]any{
			"export":     "devices",
			"columns":    []string{"Hostname", "Platform", "OS version"},
			"rows":       rows,
			"total_rows": len(rows),
		})
		if err != nil {
			t.Fatal(err)
		}
		bareDo(t, &failures, "POST /v1/portal/exports/table-pdf devices", http.MethodPost,
			"/v1/portal/exports/table-pdf", g.adminToken, strings.NewReader(string(pdfBody)))
	}

	t.Logf("walked %d report types (%d generated, %d downloads) plus the device roster export", len(types), generated, downloads)
	if len(failures) > 0 {
		lines := make([]string, len(failures))
		for i, f := range failures {
			lines[i] = f.String()
		}
		t.Errorf("%d request(s) answered 5xx for a tenant holding a device with only the required columns:\n  %s",
			len(failures), strings.Join(lines, "\n  "))
	}
}
