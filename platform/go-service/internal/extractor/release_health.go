package extractor

import "encoding/json"

// releaseHealthSnapshotComplete mirrors upsertAgentHealth's recovery contract:
// an explicit degraded array, no entries lost to malformed input or capping,
// and one completed upsert for every reported entry. written counts successful
// writes, not distinct persisted keys (duplicate keys produce the same state).
// Observe additionally requires THIS collection's accepted health watermark.
func releaseHealthSnapshotComplete(raw json.RawMessage, written, dropped int) bool {
	envelope, present := parseAgentHealth(raw, nil)
	return present && dropped == 0 && len(*envelope.Degraded) == written
}
