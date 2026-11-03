package main

import (
	"encoding/csv"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"patched.im/api/internal/portalauth"
)

func TestPAT2539UnknownOSCSV(t *testing.T) {
	f := pat2393Fixture(t)
	_, bareID := pat2538SeedDevices(t, f)
	f.exec(t, `UPDATE devices SET hostname='=fixture',serial='+fixture' WHERE id=$1::uuid`, bareID)
	for _, query := range []string{"?format=csv", "?format=csv&bucket=os_not_reported&limit=1&offset=99"} {
		req := httptest.NewRequest(http.MethodGet, "/v1/portal/mdm/jamf/coverage"+query, nil)
		req.Header.Set(portalauth.Header, f.admin)
		rr := httptest.NewRecorder()
		f.router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("CSV status=%d: %s", rr.Code, rr.Body.String())
		}
		rows, err := csv.NewReader(strings.NewReader(rr.Body.String())).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		found := 0
		for _, row := range rows[1:] {
			if row[0] != "os_not_reported" {
				continue
			}
			found++
			if row[1] != bareID || row[2] != "'=fixture" || row[3] != "'+fixture" || row[14] != "" {
				t.Errorf("unknown OS CSV identity/privacy = %v", row)
			}
		}
		if found != 1 {
			t.Errorf("unknown OS CSV rows=%d, want 1", found)
		}
	}
}
