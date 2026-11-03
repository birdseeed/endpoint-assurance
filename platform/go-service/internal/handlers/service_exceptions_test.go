package handlers

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sys/unix"
)

func TestServiceExceptionsReadFailureIsUnknown(t *testing.T) {
	// A private loopback port, no inherited connection configuration or provider.
	pool, err := pgxpool.New(context.Background(), "postgres://fixture:fixture@127.0.0.1:1/fixture?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	rr := httptest.NewRecorder()
	NewServiceExceptionsHandler(pool, t.TempDir()).ServeHTTP(rr, httptest.NewRequest("GET", "/admin/service-exceptions?tenant_id=arbitrary&path=/private", nil).WithContext(ctx))
	var got serviceExceptionsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if rr.Code != 200 || got.Coverage != "partial" || len(got.Checks) != 11 || got.Exceptions == nil || len(got.Exceptions) != 0 {
		t.Fatalf("unexpected feed: %s", rr.Body.String())
	}
	for _, i := range []int{1, 3, 7, 8} {
		c := got.Checks[i]
		if c.Availability != "degraded" || c.Result != "unknown" || c.LastSuccessAt != nil || c.NextExpectedAt != nil {
			t.Fatalf("read failure painted healthy: %+v", c)
		}
	}
	for _, private := range []string{"fixture:fixture", "127.0.0.1", t.TempDir(), "arbitrary", "/private"} {
		if strings.Contains(rr.Body.String(), private) {
			t.Fatalf("private source leaked: %q", private)
		}
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("admin evidence must not be cached")
	}
}

func TestServiceExceptionsBackupEvidence(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	recent := now.Add(-time.Hour)
	old := now.Add(-27 * time.Hour)
	for _, tc := range []struct {
		name, status string
		last         *time.Time
		want         string
		exceptions   int
	}{
		{"success is not restore proof", "ok", &recent, "unknown", 0},
		{"stale success", "success", &old, "stale", 1},
		{"explicit failure", "fail", &recent, "failed", 1},
		{"first run failed", "failed", nil, "failed", 1},
		{"unknown status", "private-value", &recent, "unknown", 0},
		{"missing success", "ok", nil, "unknown", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			raw, _ := json.Marshal(backupJobResp{Job: "db-r2", Status: tc.status, LastSuccessAt: tc.last, Label: "private@example.invalid", Detail: "/private/report.pdf"})
			file := filepath.Join(dir, "db-r2.json")
			if err := os.WriteFile(file, raw, 0600); err != nil {
				t.Fatal(err)
			}
			received := now.Add(-time.Minute)
			if err := os.Chtimes(file, received, received); err != nil {
				t.Fatal(err)
			}
			checks := serviceChecks()
			c := &checks[7]
			out := []serviceException{}
			NewServiceExceptionsHandler(nil, dir).readServiceBackups(c, &out, now)
			if c.Result != tc.want || len(out) != tc.exceptions {
				t.Fatalf("got %+v / %+v", c, out)
			}
			if len(out) > 0 {
				want := received
				if tc.want == "stale" {
					want = *tc.last
				}
				if !out[0].EvidenceAt.Equal(want) || out[0].Since != nil || out[0].TenantID != nil {
					t.Fatalf("invented evidence: %+v", out[0])
				}
			}
			encoded, _ := json.Marshal(struct {
				Check      *serviceCheck
				Exceptions []serviceException
			}{c, out})
			if strings.Contains(string(encoded), "private") || strings.Contains(string(encoded), dir) {
				t.Fatal("private heartbeat fields leaked")
			}
			if c.LastSuccessAt != nil || !strings.Contains(c.Reason, "Restore-test") {
				t.Fatal("aggregate backup success is not proven")
			}
		})
	}
}

func TestServiceExceptionsUnsafeBackupFiles(t *testing.T) {
	now := time.Now().UTC()
	for _, kind := range []string{"malformed", "oversize", "future-success", "future-receipt", "symlink", "directory", "fifo", "mismatched-job", "empty", "missing", "unconfigured", "root-symlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			file := filepath.Join(dir, "db-r2.json")
			raw := `{"job":"db-r2","status":"fail","last_success_at":null}`
			switch kind {
			case "malformed":
				raw = "{"
			case "oversize":
				raw = strings.Repeat("x", maxBackupHeartbeatBytes+1)
			case "future-success":
				raw = `{"job":"db-r2","status":"ok","last_success_at":"2999-01-01T00:00:00Z"}`
			case "mismatched-job":
				raw = `{"job":"../../private","status":"fail"}`
			}
			if err := os.WriteFile(file, []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			// Place the normal receipt before the fixed clock; no wall-clock races.
			past := now.Add(-time.Minute)
			if err := os.Chtimes(file, past, past); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "future-receipt":
				if err := os.Chtimes(file, now.Add(time.Hour), now.Add(time.Hour)); err != nil {
					t.Fatal(err)
				}
			case "symlink", "directory", "fifo", "empty":
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "symlink":
					target := filepath.Join(t.TempDir(), "private.json")
					if err := os.WriteFile(target, []byte(raw), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(target, file); err != nil {
						t.Fatal(err)
					}
				case "directory":
					if err := os.Mkdir(file, 0700); err != nil {
						t.Fatal(err)
					}
				case "fifo":
					if err := unix.Mkfifo(file, 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "missing":
				dir = filepath.Join(dir, "missing")
			case "unconfigured":
				dir = ""
			case "root-symlink":
				link := filepath.Join(t.TempDir(), "linked")
				if err := os.Symlink(dir, link); err != nil {
					t.Fatal(err)
				}
				dir = link
			}
			checks := serviceChecks()
			c := &checks[7]
			out := []serviceException{}
			NewServiceExceptionsHandler(nil, dir).readServiceBackups(c, &out, now)
			if c.Result != "unknown" || len(out) != 0 {
				t.Fatalf("unsafe evidence interpreted: %+v / %+v", c, out)
			}
		})
	}
}

func TestServiceEvidenceTimes(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	future := now.Add(time.Nanosecond)
	zero := time.Time{}
	old := time.Date(1969, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, v := range []*time.Time{nil, &future, &zero, &old} {
		if serviceTime(v, now) != nil {
			t.Fatal("invalid timestamp accepted")
		}
	}
	offset := now.In(time.FixedZone("offset", 3600))
	if got := serviceTime(&offset, now); got == nil || got.Location() != time.UTC || !got.Equal(now) {
		t.Fatal("valid boundary timestamp must remain UTC")
	}
}
