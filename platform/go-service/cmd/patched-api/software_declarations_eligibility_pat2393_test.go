package main

// Supplemental parent-requested contract: one conservative Windows eligibility
// decision must reach posture, governance/lifecycle and inventory reporting.
import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/agentconfig"
	"patched.im/api/internal/handlers"
	"patched.im/api/internal/softwaregov"
)

func TestPAT2393EligibilitySuspendsAndRestoresAcrossReaders(t *testing.T) {
	f := pat2393Fixture(t)
	alias, identifier := f.alias(t, "windows", "windows_native_publisher", "synthetic publisher")
	body := pat2393Body("windows")
	body["alias_id"] = alias
	id := pat2393ID(t, f.create(t, body))
	hwGood, hwBad := "12392393-0000-4000-8000-000000000030", "12392393-0000-4000-8000-000000000031"
	now := time.Now().Add(-time.Minute)
	app := pat2393WindowsApp(identifier, "CN=Synthetic Publisher", "valid")
	f.observeFixture(t, "full-v3-windows.json", hwGood, []map[string]any{app}, now)
	f.request(t, "POST", declarationPath+"/"+id+"/resolve", f.admin, map[string]any{"alias_id": alias, "justification": "Verified key"}, 200)
	// Less specific authored deny demonstrates that suspended approval cannot
	// mask lifecycle findings and that unrelated policies retain precedence.
	f.exec(t, `INSERT INTO tenant_app_policies(tenant_id,name,platform,policy,enforcement_tier) VALUES($1::uuid,'Synthetic Editor','windows','unapproved','report_deploy')`, f.tenant)
	var device string
	if e := f.pool.QueryRow(t.Context(), `SELECT id::text FROM devices WHERE tenant_id=$1::uuid AND hw_uuid=$2::uuid`, f.tenant, hwGood).Scan(&device); e != nil {
		t.Fatal(e)
	}
	f.exec(t, `UPDATE tenant_credentials SET device_id=$2::uuid WHERE tenant_id=$1::uuid`, f.tenant, device)
	check := func(want string) {
		t.Helper()
		estate, e := softwaregov.LoadEstate(t.Context(), f.pool, f.tenant, time.Now())
		if e != nil {
			t.Fatal(e)
		}
		found := false
		for _, a := range estate.Assessments {
			if a.Identifier == identifier {
				found = true
				if a.State != want {
					t.Fatalf("governance state=%s want %s", a.State, want)
				}
			}
		}
		if !found {
			t.Fatal("governance observation missing")
		}
		rr := f.request(t, "GET", "/v1/portal/software?search="+identifier, f.admin, nil, 200)
		if !strings.Contains(rr.Body.String(), `"policy_state":"`+want+`"`) {
			t.Fatalf("inventory state missing: %s", rr.Body.String())
		}
		seed := make([]byte, 32)
		seed[0] = 1
		key, e := agentconfig.KeyFromSeed(seed)
		if e != nil {
			t.Fatal(e)
		}
		req := httptest.NewRequest("GET", "/v1/posture", nil)
		mac := hmac.New(sha256.New, f.secret)
		req.Header.Set("Authorization", "Bearer "+f.bearer)
		req.Header.Set("X-Patched-Signature", hex.EncodeToString(mac.Sum(nil)))
		req.Header.Set("X-Patched-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
		req.Header.Set("X-Patched-Nonce", pat2393Random())
		rec := httptest.NewRecorder()
		handlers.PostureHandler(f.pool, key, nil, 5*time.Minute).ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("posture=%d %s", rec.Code, rec.Body.String())
		}
		var envelope struct {
			Payload string `json:"signed_payload"`
		}
		if e = json.Unmarshal(rec.Body.Bytes(), &envelope); e != nil {
			t.Fatal(e)
		}
		raw, e := base64.StdEncoding.DecodeString(envelope.Payload)
		if e != nil {
			t.Fatal(e)
		}
		var posture struct {
			AppPolicy struct {
				Apps []struct{ Identifier, Policy string }
			} `json:"app_policy"`
		}
		if e = json.Unmarshal(raw, &posture); e != nil {
			t.Fatal(e)
		}
		matched := false
		for _, a := range posture.AppPolicy.Apps {
			if a.Identifier == identifier {
				matched = true
				if a.Policy != want {
					t.Fatalf("posture=%s want %s", a.Policy, want)
				}
			}
		}
		if !matched {
			t.Fatalf("posture omitted policy: %s", raw)
		}
	}
	check("approved")
	f.observeFixture(t, "full-v3-windows.json", hwBad, []map[string]any{pat2393WindowsApp(identifier, "", "unsigned")}, now.Add(time.Second))
	check("unapproved")
	pat2393Equal(t, f.row(t, id), "approval_state", "approved")
	f.observeFixture(t, "full-v3-windows.json", hwBad, []map[string]any{}, now.Add(2*time.Second))
	check("approved")
	history := pat2393JSON(t, f.request(t, "GET", declarationPath+"/"+id+"/history", f.admin, nil, 200))
	if len(history["decisions"].([]any)) != 2 {
		t.Fatal("eligibility suspension changed authored decision history")
	}
}
