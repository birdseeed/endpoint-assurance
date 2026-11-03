//go:build integration

package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/handlers"
)

func TestPAT1966DailyJobObservationBoundary(t *testing.T) {
	for _, job := range []string{"health_signals_recompute", "api01_backup", "prod01_backup", "portal01_backup"} {
		t.Run(job, func(t *testing.T) {
			for _, tc := range []struct {
				name  string
				age   time.Duration
				stale bool
			}{
				{"30h current", 30 * time.Hour, false},
				{"35h59m current", 35*time.Hour + 59*time.Minute, false},
				{"36h1m stale", 36*time.Hour + time.Minute, true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					// pat1966Job adds one minute to started_at. Set the completed age,
					// without changing wall time or the production observation limit.
					finished := pat1966Job(t, job, "success", time.Now().Add(-tc.age-time.Minute))
					f := pat1966Get(t)
					failures := pat1966JobExceptions(f, job)
					want := 0
					if tc.stale {
						want = 1
					}
					if len(failures) != want {
						t.Fatalf("%s completed observation: got %d exceptions, want %d under existing 36-hour UI heuristic", tc.name, len(failures), want)
					}
					var observations []map[string]json.RawMessage
					if err := json.Unmarshal(pat1966Check(t, f, "scheduled_jobs")["observations"], &observations); err != nil {
						t.Fatal(err)
					}
					found := false
					for _, observation := range observations {
						if pat1966String(observation, "id") != job {
							continue
						}
						found = true
						result := "ok"
						if tc.stale {
							result = "stale"
						}
						var at, success time.Time
						if pat1966String(observation, "result") != result || json.Unmarshal(observation["evidence_at"], &at) != nil || !at.Equal(finished) || json.Unmarshal(observation["last_success_at"], &success) != nil || !success.Equal(finished) {
							t.Error("job result and completed success evidence must be retained")
						}
					}
					if !found {
						t.Fatal("active job observation missing")
					}
					if string(pat1966Check(t, f, "scheduled_jobs")["next_expected_at"]) != "null" {
						t.Error("coarse observation heuristic cannot invent next schedule")
					}
					if tc.stale {
						var at time.Time
						if json.Unmarshal(failures[0]["evidence_at"], &at) != nil || !at.Equal(finished) || string(failures[0]["since"]) != "null" {
							t.Error("stale observation cannot invent onset or change completion evidence")
						}
						if reason := pat1966String(failures[0], "reason"); !strings.Contains(reason, "coarse 36-hour UI heuristic") || !strings.Contains(reason, "does not establish a missed timer schedule") {
							t.Error("job reason must name the existing coarse heuristic and preserve schedule uncertainty")
						}
					}
				})
			}
		})
	}
}

func TestPAT1966Backup28HoursRemainsStale(t *testing.T) {
	dir := t.TempDir()
	last := time.Now().Add(-28 * time.Hour).UTC().Truncate(time.Microsecond)
	raw, err := json.Marshal(map[string]any{"job": "db-r2", "status": "ok", "last_success_at": last, "label": pat1966Private, "detail": pat1966Private})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "db-r2.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	// Use the actual HTTP handler and a real private DB, with owned heartbeat files.
	srv := httptest.NewServer(handlers.NewServiceExceptionsHandler(env.pool, dir))
	defer srv.Close()
	resp, err := http.Get(srv.URL + pat1966Path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("backup feed status %d", resp.StatusCode)
	}
	if strings.Contains(string(body), "PAT1966_PRIVATE_SENTINEL") || strings.Contains(string(body), dir) {
		t.Fatal("private heartbeat data leaked")
	}
	var f pat1966Feed
	if err := json.Unmarshal(body, &f); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, e := range f.Exceptions {
		if pat1966String(e, "id") != "backups:db-r2" {
			continue
		}
		count++
		var evidence time.Time
		if json.Unmarshal(e["evidence_at"], &evidence) != nil || !evidence.Equal(last) || string(e["since"]) != "null" || !strings.Contains(pat1966String(e, "reason"), "26-hour") {
			t.Error("backup must keep 26-hour provenance and actual evidence")
		}
	}
	if count != 1 {
		t.Fatalf("28-hour backup: got %d exceptions, want one", count)
	}
}
