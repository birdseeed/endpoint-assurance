package extractor

import (
	"fmt"
	"strings"
	"time"
)

func validateAppUsageEvidence(app map[string]any, i int) error {
	raw, present := app["usage_evidence"]
	if !present {
		return nil
	} // Older agent: PAT-2327 remains the baseline.
	state, ok := raw.(string)
	if !ok {
		return fmt.Errorf("apps[%d].usage_evidence: must be a string", i)
	}
	switch state {
	case "recorded", "no_record", "unmapped", "unavailable":
	default:
		return fmt.Errorf("apps[%d].usage_evidence: unknown state", i)
	}
	// Partial reads can retain a positive value while declaring unavailable;
	// that value is historical evidence, never current non-use authority.
	positive := false
	if raw := app["last_used_at"]; raw != nil {
		value, ok := raw.(string)
		if !ok {
			return fmt.Errorf("apps[%d].last_used_at: must be RFC3339", i)
		}
		if _, err := time.Parse(time.RFC3339, value); err != nil {
			return fmt.Errorf("apps[%d].last_used_at: must be RFC3339", i)
		}
		positive = true
	}
	if count, ok := app["launch_count"].(float64); ok && count > 0 {
		positive = true
	}
	if state == "recorded" && !positive {
		return fmt.Errorf("apps[%d].usage_evidence: recorded requires a timestamp or positive count", i)
	}
	if state == "unmapped" && (app["last_used_at"] != nil || app["launch_count"] != nil) {
		return fmt.Errorf("apps[%d].usage_evidence: unmapped requires null or absent usage values", i)
	}
	if state == "no_record" && (app["last_used_at"] != nil || (app["launch_count"] != nil && app["launch_count"] != float64(0))) {
		return fmt.Errorf("apps[%d].usage_evidence: no_record requires no timestamp and null or zero count", i)
	}
	if raw, present := app["launch_count"]; present && raw != nil {
		n, ok := raw.(float64)
		if !ok || n < 0 || n > 2147483647 || n != float64(int64(n)) {
			return fmt.Errorf("apps[%d].launch_count: must be a non-negative integer", i)
		}
	}
	return nil
}

// Inventory completeness is independent of the raw per-app observation.
// No explicit collection signal cannot establish current non-use authority.
func usageEvidenceComplete(signal appsSignal, user string, completeUsers []string) bool {
	if user == "" {
		return signal == appsSignalComplete
	}
	for _, completeUser := range completeUsers {
		if completeUser == user {
			return true
		}
	}
	return false
}

// Several user scopes can share one device_apps row. Conflicting observations
// have no single authoritative usage state; retain their raw payloads and make
// the shared projection unavailable, independent of input order.
func appUsageConflicts(apps []appPart) map[string]bool {
	first := make(map[string]appPart)
	conflicts := make(map[string]bool)
	for _, app := range apps {
		if _, valid := appsUserKey(app.UserAccount); !valid {
			continue
		}
		key := appUsageKey(app)
		if previous, ok := first[key]; ok {
			if !sameOptional(previous.UsageEvidence, app.UsageEvidence) ||
				!sameOptional(previous.LastUsedAt, app.LastUsedAt) ||
				!sameOptional(previous.LaunchCount, app.LaunchCount) ||
				previous.UserAccount != app.UserAccount {
				conflicts[key] = true
			}
		} else {
			first[key] = app
		}
	}
	return conflicts
}

func appUsageKey(app appPart) string {
	identifier := strings.TrimSpace(app.Identifier)
	if identifier == "" {
		identifier = strings.TrimSpace(app.BundleID)
	}
	return identifier + "\x00" + app.Version
}

func sameOptional[T comparable](a, b *T) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}
