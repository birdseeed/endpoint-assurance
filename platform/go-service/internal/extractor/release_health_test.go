package extractor

import (
	"encoding/json"
	"testing"
)

func TestReleaseHealthSnapshotCompleteness(t *testing.T) {
	for _, raw := range []json.RawMessage{nil, []byte(`null`), []byte(`{}`), []byte(`{"degraded":null}`), []byte(`{"degraded":"malformed"}`)} {
		if releaseHealthSnapshotComplete(raw, 0, 0) {
			t.Fatalf("incomplete section accepted %s", raw)
		}
	}
	if !releaseHealthSnapshotComplete([]byte(`{"degraded":[]}`), 0, 0) {
		t.Fatal("explicit all-clear rejected")
	}
	channelOnly := json.RawMessage(`{"update_channel":{"channel":"beta","source":"tenant","config_version":3}}`)
	if releaseHealthSnapshotComplete(channelOnly, 0, 0) {
		t.Fatal("channel observation alone established complete health")
	}
	entry := json.RawMessage(`{"kind":"upload","subject":"inventory","reason":"failure","first_seen":"2026-09-27T00:00:00Z","last_seen":"2026-09-27T00:00:00Z","count":1,"ever_succeeded":false}`)
	for _, tc := range []struct {
		name    string
		entries []json.RawMessage
		want    bool
	}{{"complete", []json.RawMessage{entry}, true}, {"dropped", []json.RawMessage{entry, []byte(`{}`)}, false}, {"malformed", []json.RawMessage{[]byte(`"bad"`)}, false}, {"capped", make([]json.RawMessage, agentHealthMaxEntries+1), false}} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "capped" {
				for i := range tc.entries {
					tc.entries[i] = entry
				}
			}
			sanitized := sanitizeAgentHealthEntries(tc.entries, "device", nil)
			raw, _ := json.Marshal(map[string]any{"degraded": tc.entries})
			if got := releaseHealthSnapshotComplete(raw, len(sanitized.Entries), sanitized.Dropped); got != tc.want {
				t.Fatalf("complete=%v dropped=%d capped=%v", got, sanitized.Dropped, sanitized.Capped)
			}
			if releaseHealthSnapshotComplete(raw, 0, 0) && len(tc.entries) > 0 {
				t.Fatal("unwritten set accepted")
			}
		})
	}
}
