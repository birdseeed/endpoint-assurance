//go:build integration

package integration

// PAT-2496: one definition of a device's disk-encryption state.
//
// A customer's cyber insurance evidence pack said a Windows device "reported
// no encryption state" while the Devices roster, the device page and the
// Compliance tab all showed the same device as not encrypted. The pack and the
// Encryption & Disk Posture report read compliance_signals key "bitlocker",
// which no agent writes (the Windows agent writes "bitlocker_os_drive"), while
// the roster read the CIS rule evaluations.
//
// These tests build their fixture the way production data arrives: real-shaped
// agent payloads are POSTed to /v1/inventory and run through the extractor, so
// the signals carry the keys the agents send and the evaluations are the ones
// the evaluator produced. Nothing is hand-seeded into compliance_signals under
// a key an agent does not use. Every surface that states a device's encryption
// is then read over HTTP and must agree:
//
//   - GET /v1/portal/devices (roster) and GET /v1/portal/devices/{id} (device
//     page), through encryption_ok;
//   - GET /v1/portal/insurance-evidence, as JSON and as CSV;
//   - the Encryption & Disk Posture report, as CSV (the state column);
//   - the Compliance tab entries of the device page, through undetermined.

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/extractor"
	"patched.im/api/internal/report"
)

// The two disk-encryption rules whose latest evaluation decides a device's
// state, as the roster reads them.
const (
	pat2496MacRule = "cis_macos_2_5_1_1_filevault"
	pat2496WinRule = "cis_win_18_10_11_bitlocker_os_drive"
)

const (
	pat2496Encrypted    = "encrypted"
	pat2496NotEncrypted = "not_encrypted"
	pat2496Unknown      = "unknown"
)

// pat2496Device is one agent payload to ingest. signal is the compliance key
// the agent sends for disk encryption (filevault on macOS, bitlocker_os_drive
// on Windows); value is what it reports. An empty signal sends no encryption
// key at all, the shape of an agent that could not read the state.
type pat2496Device struct {
	hostname string
	windows  bool
	signal   string
	value    string
	want     string // expected state: encrypted, not_encrypted or unknown
}

type pat2496Estate struct {
	token   string
	tenant  string
	devices map[string]string // hostname -> device id
}

func pat2496UUID() string {
	h := randomHex(16)
	return strings.ToUpper(fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32]))
}

// pat2496Payload builds one agent payload from the repository's own golden
// fixtures (macOS schema 2, Windows schema 3), changing only the identity and
// the disk-encryption signal so everything else stays a payload the validator
// accepts today.
func pat2496Payload(t *testing.T, d pat2496Device) []byte {
	t.Helper()
	fixture := "minimal.json"
	if d.windows {
		fixture = "full-v3-windows.json"
	}
	var p map[string]any
	if err := json.Unmarshal(fixtureData(t, "valid", fixture), &p); err != nil {
		t.Fatalf("decode fixture %s: %v", fixture, err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	p["collected_at"] = now
	dev := p["device"].(map[string]any)
	dev["serial"] = "PAT2496" + strings.ToUpper(randomHex(4))
	dev["hw_uuid"] = pat2496UUID()
	dev["hostname"] = d.hostname
	dev["last_boot"] = now
	comp := p["compliance"].(map[string]any)
	delete(comp, "filevault")
	delete(comp, "bitlocker_os_drive")
	if d.signal != "" {
		comp[d.signal] = d.value
	}
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return body
}

// pat2496Ingest creates a tenant, a portal user for it, ingests every device
// through the real endpoint and extractor, and returns the portal token and
// the hostname -> device id map.
func pat2496Ingest(t *testing.T, label string, devices []pat2496Device) pat2496Estate {
	t.Helper()
	ctx := context.Background()
	name := "pat2496-" + label + "-" + randomHex(3)
	tenantID, bearer, secret, err := createTestTenant(env.internalSrv.URL, name)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	// No cleanupTestTenant: a real-shaped Windows payload opens findings, and
	// finding_lifecycle_events is append-only, so the tenant cannot be deleted.
	// The tenant is unique per run and the database is a throwaway.
	email := "viewer@" + name + ".example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)

	for _, d := range devices {
		resp := postInventory(t, signedInventoryRequestWithAuth(t, bearer, secret, pat2496Payload(t, d)))
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("POST /v1/inventory (%s) = %d: %s", d.hostname, resp.StatusCode, raw)
		}
	}
	if err := extractor.ProcessOnce(ctx, env.pool); err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}

	ids := map[string]string{}
	rows, err := env.pool.Query(ctx, `SELECT hostname, id::text FROM devices WHERE tenant_id = $1::uuid`, tenantID)
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var host, id string
		if err := rows.Scan(&host, &id); err != nil {
			t.Fatalf("scan device: %v", err)
		}
		ids[host] = id
	}
	if len(ids) != len(devices) {
		t.Fatalf("extracted %d devices, want %d (%v)", len(ids), len(devices), ids)
	}
	return pat2496Estate{token: env.idp.token(t, email), tenant: tenantID, devices: ids}
}

func pat2496StateOfOK(ok *bool) string {
	switch {
	case ok == nil:
		return pat2496Unknown
	case *ok:
		return pat2496Encrypted
	}
	return pat2496NotEncrypted
}

func pat2496GetJSON(t *testing.T, token, path string, out any) {
	t.Helper()
	resp := portalDo(t, http.MethodGet, path, token, nil)
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("GET %s = %d: %s", path, resp.StatusCode, raw)
	}
	decodeJSON(t, resp, out)
}

// pat2496Roster returns hostname -> state as the Devices roster states it.
func pat2496Roster(t *testing.T, e pat2496Estate) map[string]string {
	t.Helper()
	var out struct {
		Devices []struct {
			Hostname     string `json:"hostname"`
			EncryptionOK *bool  `json:"encryption_ok"`
		} `json:"devices"`
	}
	pat2496GetJSON(t, e.token, "/v1/portal/devices?limit=500", &out)
	got := map[string]string{}
	for _, d := range out.Devices {
		got[d.Hostname] = pat2496StateOfOK(d.EncryptionOK)
	}
	return got
}

type pat2496Detail struct {
	Device struct {
		EncryptionOK *bool `json:"encryption_ok"`
	} `json:"device"`
	ComplianceSignals []struct {
		RuleID       string `json:"rule_id"`
		Status       string `json:"status"`
		Undetermined *bool  `json:"undetermined"`
	} `json:"compliance_signals"`
}

func pat2496DeviceDetail(t *testing.T, e pat2496Estate, host string) pat2496Detail {
	t.Helper()
	var out pat2496Detail
	pat2496GetJSON(t, e.token, "/v1/portal/devices/"+e.devices[host], &out)
	return out
}

type pat2496Pack struct {
	Questions []struct {
		ID         string `json:"id"`
		Status     string `json:"status"`
		AnswerText string `json:"answer_text"`
		Answer     struct {
			Value  *int           `json:"value"`
			Counts map[string]int `json:"counts"`
		} `json:"answer"`
	} `json:"questions"`
}

func (p pat2496Pack) encryption(t *testing.T) (text string, counts map[string]int) {
	t.Helper()
	for _, q := range p.Questions {
		if q.ID == "disk_encryption" {
			return q.AnswerText, q.Answer.Counts
		}
	}
	t.Fatal("disk_encryption question missing from the pack")
	return "", nil
}

// pat2496PostureCSV returns hostname -> column -> cell for the device rows of
// the Encryption & Disk Posture report's CSV, generated through the portal like
// a customer would.
func pat2496PostureCSV(t *testing.T, e pat2496Estate) map[string]map[string]string {
	t.Helper()
	id := pat2405Generate(t, e.token, "encryption-posture", "pat2496-posture")
	d := pat2405Get(t, e.token, id, "format=csv")
	if d.status != http.StatusOK {
		t.Fatalf("posture csv = %d (%.200q)", d.status, d.body)
	}
	table := pat2405ParseCSV(t, d.body)
	header := table[0]
	section, host := pat2405Col(t, header, "section"), pat2405Col(t, header, "hostname")
	got := map[string]map[string]string{}
	for _, r := range table[1:] {
		if r[section] != "device" {
			continue
		}
		row := map[string]string{}
		for i, h := range header {
			row[h] = r[i]
		}
		got[r[host]] = row
	}
	return got
}

// pat2496PostureStates is hostname -> state from the posture CSV.
func pat2496PostureStates(t *testing.T, e pat2496Estate) map[string]string {
	t.Helper()
	states := map[string]string{}
	for host, row := range pat2496PostureCSV(t, e) {
		states[host] = row["state"]
	}
	return states
}

func pat2496Tally(states map[string]string) map[string]int {
	n := map[string]int{pat2496Encrypted: 0, pat2496NotEncrypted: 0, pat2496Unknown: 0}
	for _, s := range states {
		n[s]++
	}
	return n
}

// TestPAT2496_EncryptionStateAgreesAcrossSurfaces is the customer's case: one
// encrypted Mac, one Windows device whose BitLocker is observed off and one
// device that reports no readable encryption state.
func TestPAT2496_EncryptionStateAgreesAcrossSurfaces(t *testing.T) {
	devices := []pat2496Device{
		{hostname: "pat2496-mac-on", signal: "filevault", value: "On", want: pat2496Encrypted},
		{hostname: "pat2496-win-off", windows: true, signal: "bitlocker_os_drive", value: "Off", want: pat2496NotEncrypted},
		{hostname: "pat2496-win-nostate", windows: true, signal: "bitlocker_os_drive", value: "Unknown", want: pat2496Unknown},
	}
	e := pat2496Ingest(t, "agree", devices)
	want := map[string]string{}
	for _, d := range devices {
		want[d.hostname] = d.want
	}

	// Roster and device page: the two surfaces the customer saw agree.
	roster := pat2496Roster(t, e)
	for _, d := range devices {
		if roster[d.hostname] != d.want {
			t.Errorf("roster %s = %q, want %q", d.hostname, roster[d.hostname], d.want)
		}
		detail := pat2496DeviceDetail(t, e, d.hostname)
		if got := pat2496StateOfOK(detail.Device.EncryptionOK); got != d.want {
			t.Errorf("device page %s encryption_ok = %q, want %q", d.hostname, got, d.want)
		}
	}

	// The insurance evidence pack: one device in each outcome, never merged.
	var pack pat2496Pack
	pat2496GetJSON(t, e.token, "/v1/portal/insurance-evidence", &pack)
	text, counts := pack.encryption(t)
	for k, v := range map[string]int{"devices_in_scope": 3, "encrypted": 1, "not_encrypted": 1, "no_evidence": 1, "not_reporting": 0} {
		if counts[k] != v {
			t.Errorf("pack counts[%s] = %d, want %d (all %v)", k, counts[k], v, counts)
		}
	}
	const wantText = "1 of 3 devices (33.3%) reports FileVault or BitLocker full-disk encryption turned on. " +
		"1 device reports encryption turned off. " +
		"Encryption is turned off on: pat2496-win-off. " +
		"1 device is unknown (1 reported no encryption state) and is not counted in your favour."
	if text != wantText {
		t.Errorf("pack answer\n got: %q\nwant: %q", text, wantText)
	}

	// The same pack as CSV carries the same answer.
	resp := portalDo(t, http.MethodGet, "/v1/portal/insurance-evidence?format=csv", e.token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pack csv = %d", resp.StatusCode)
	}
	rows, err := csv.NewReader(resp.Body).ReadAll()
	resp.Body.Close()
	if err != nil {
		t.Fatalf("parse pack csv: %v", err)
	}
	idCol, textCol, countsCol := pat2405Col(t, rows[0], "question_id"), pat2405Col(t, rows[0], "answer_text"), pat2405Col(t, rows[0], "counts")
	var csvText, csvCounts string
	for _, r := range rows[1:] {
		if r[idCol] == "disk_encryption" {
			csvText, csvCounts = r[textCol], r[countsCol]
		}
	}
	if csvText != text {
		t.Errorf("pack csv answer %q differs from json answer %q", csvText, text)
	}
	if !strings.Contains(csvCounts, "not_encrypted=1") || !strings.Contains(csvCounts, "no_evidence=1") || !strings.Contains(csvCounts, "encrypted=1") {
		t.Errorf("pack csv counts %q", csvCounts)
	}

	// The posture report's CSV, device by device and in total, and beside
	// each state the raw value the agent sent under the key it really uses.
	detail := pat2496PostureCSV(t, e)
	posture := map[string]string{}
	for host, row := range detail {
		posture[host] = row["state"]
	}
	for host, w := range want {
		if posture[host] != w {
			t.Errorf("posture csv %s state = %q, want %q", host, posture[host], w)
		}
	}
	for host, c := range map[string][2]string{
		"pat2496-mac-on":      {"On", ""},
		"pat2496-win-off":     {"", "Off"},
		"pat2496-win-nostate": {"", "Unknown"},
	} {
		if detail[host]["filevault"] != c[0] || detail[host]["bitlocker"] != c[1] {
			t.Errorf("posture csv %s raw values = filevault %q bitlocker %q, want %q / %q (the agent sends bitlocker_os_drive)",
				host, detail[host]["filevault"], detail[host]["bitlocker"], c[0], c[1])
		}
	}
	tally := pat2496Tally(posture)
	if tally[pat2496Encrypted] != counts["encrypted"] || tally[pat2496NotEncrypted] != counts["not_encrypted"] || tally[pat2496Unknown] != counts["no_evidence"] {
		t.Errorf("posture csv tally %v disagrees with the pack's counts %v", tally, counts)
	}

	// The one definition itself, for the whole tenant and for one device,
	// and the posture report's totals (what its PDF prints) built on it.
	ctx := context.Background()
	all, err := report.FetchEncryptionStates(ctx, env.pool, e.tenant, nil)
	if err != nil {
		t.Fatalf("FetchEncryptionStates: %v", err)
	}
	for _, d := range devices {
		id := e.devices[d.hostname]
		if all[id] != d.want {
			t.Errorf("FetchEncryptionStates(all) %s = %q, want %q", d.hostname, all[id], d.want)
		}
		one, err := report.FetchEncryptionStates(ctx, env.pool, e.tenant, []string{id})
		if err != nil || len(one) != 1 || one[id] != d.want {
			t.Errorf("FetchEncryptionStates(one) %s = %v, %v; want %q", d.hostname, one, err, d.want)
		}
	}
	rep, err := report.FetchEncryptionPostureReport(ctx, env.pool, e.tenant)
	if err != nil {
		t.Fatalf("FetchEncryptionPostureReport: %v", err)
	}
	if rep.EncryptedCount != 1 || rep.UnencryptedCount != 1 || rep.UnknownCount != 1 {
		t.Errorf("posture report counts = %d encrypted / %d unencrypted / %d unknown, want 1 / 1 / 1",
			rep.EncryptedCount, rep.UnencryptedCount, rep.UnknownCount)
	}

	// The Compliance tab: a rule that failed only because the value was
	// unreadable says so; a rule that failed on an observed value does not.
	wantUndetermined := map[string]bool{"pat2496-mac-on": false, "pat2496-win-off": false, "pat2496-win-nostate": true}
	for host, wu := range wantUndetermined {
		var seen bool
		var missing []string
		for _, s := range pat2496DeviceDetail(t, e, host).ComplianceSignals {
			if s.Undetermined == nil {
				missing = append(missing, s.RuleID)
			}
			if s.RuleID != pat2496MacRule && s.RuleID != pat2496WinRule {
				continue
			}
			seen = true
			if s.Undetermined != nil && *s.Undetermined != wu {
				t.Errorf("%s: %s undetermined = %v (status %s), want %v", host, s.RuleID, *s.Undetermined, s.Status, wu)
			}
		}
		if len(missing) > 0 {
			t.Errorf("%s: %d compliance entries have no undetermined field (first: %s)", host, len(missing), missing[0])
		}
		if !seen {
			t.Errorf("%s: no disk-encryption rule in the compliance entries", host)
		}
	}
}

// TestPAT2496_WindowsBitLockerOnCountsAsEncrypted is the regression for the
// root cause: a Windows device with BitLocker on is encrypted in the pack and
// in the posture report, not unknown.
func TestPAT2496_WindowsBitLockerOnCountsAsEncrypted(t *testing.T) {
	devices := []pat2496Device{
		{hostname: "pat2496-win-on", windows: true, signal: "bitlocker_os_drive", value: "On", want: pat2496Encrypted},
		{hostname: "pat2496-mac-nokey", want: pat2496Unknown},
	}
	e := pat2496Ingest(t, "winon", devices)

	var pack pat2496Pack
	pat2496GetJSON(t, e.token, "/v1/portal/insurance-evidence", &pack)
	text, counts := pack.encryption(t)
	for k, v := range map[string]int{"devices_in_scope": 2, "encrypted": 1, "not_encrypted": 0, "no_evidence": 1} {
		if counts[k] != v {
			t.Errorf("pack counts[%s] = %d, want %d (all %v; %s)", k, counts[k], v, counts, text)
		}
	}
	posture := pat2496PostureCSV(t, e)
	for _, d := range devices {
		if posture[d.hostname]["state"] != d.want {
			t.Errorf("posture csv %s state = %q, want %q", d.hostname, posture[d.hostname]["state"], d.want)
		}
	}
	if got := posture["pat2496-win-on"]["bitlocker"]; got != "On" {
		t.Errorf("posture csv win-on bitlocker = %q, want On (read from bitlocker_os_drive)", got)
	}
	if got := pat2496Roster(t, e)["pat2496-win-on"]; got != pat2496Encrypted {
		t.Errorf("roster win-on = %q, want encrypted", got)
	}
}

// pat2496FormulaHostname begins with = and would be a formula in a spreadsheet
// if it ever led a cell.
const pat2496FormulaHostname = `=HYPERLINK("http://example.invalid/x","click")`

// TestPAT2496_NamedHostnameThatBeginsWithEqualsIsNotAFormula: the pack names a
// not encrypted device by hostname, and the hostname is agent-supplied. In the
// pack's CSV the name sits inside the answer sentence, so the cell cannot start
// with =, and in the posture CSV, where the hostname leads its own cell, the
// writer's formula guard prefixes it. The pack's PDF form must still download.
func TestPAT2496_NamedHostnameThatBeginsWithEqualsIsNotAFormula(t *testing.T) {
	devices := []pat2496Device{
		{hostname: "pat2496-mac-ok", signal: "filevault", value: "On", want: pat2496Encrypted},
		{hostname: pat2496FormulaHostname, windows: true, signal: "bitlocker_os_drive", value: "Off", want: pat2496NotEncrypted},
	}
	e := pat2496Ingest(t, "formula", devices)

	var pack pat2496Pack
	pat2496GetJSON(t, e.token, "/v1/portal/insurance-evidence", &pack)
	text, _ := pack.encryption(t)
	wantSentence := "Encryption is turned off on: " + pat2496FormulaHostname + "."
	if !strings.Contains(text, wantSentence) {
		t.Errorf("pack answer %q does not contain %q", text, wantSentence)
	}

	resp := portalDo(t, http.MethodGet, "/v1/portal/insurance-evidence?format=csv", e.token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pack csv = %d", resp.StatusCode)
	}
	rows, err := csv.NewReader(resp.Body).ReadAll()
	resp.Body.Close()
	if err != nil {
		t.Fatalf("parse pack csv: %v", err)
	}
	idCol, textCol := pat2405Col(t, rows[0], "question_id"), pat2405Col(t, rows[0], "answer_text")
	var cell string
	for _, r := range rows[1:] {
		if r[idCol] == "disk_encryption" {
			cell = r[textCol]
		}
	}
	if cell == "" || strings.ContainsRune("=+-@\t\r", rune(cell[0])) {
		t.Errorf("pack csv answer cell %q must not start with a formula character", cell)
	}
	if !strings.Contains(cell, wantSentence) {
		t.Errorf("pack csv answer %q does not carry the sentence %q", cell, wantSentence)
	}

	posture := pat2496PostureCSV(t, e)
	if _, ok := posture["'"+pat2496FormulaHostname]; !ok {
		var got []string
		for h := range posture {
			got = append(got, h)
		}
		t.Errorf("posture csv hostname cell must carry the formula guard prefix; hostnames: %q", got)
	}

	pdf := portalDo(t, http.MethodGet, "/v1/portal/insurance-evidence?format=pdf", e.token, nil)
	body, _ := io.ReadAll(pdf.Body)
	pdf.Body.Close()
	if pdf.StatusCode != http.StatusOK || !strings.HasPrefix(string(body), "%PDF") {
		t.Errorf("pack pdf = %d, %.8q", pdf.StatusCode, body)
	}
}
