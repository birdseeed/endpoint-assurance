package handlers

// TenantAppPolicyDriftHandler aggregates app-policy drift signals across all
// active devices for a tenant (PAT-479 / D2 staff-side drift surfacing).
//
// Drift is computed by joining tenant_app_policies against device_apps using
// the same conjunctive full-tuple matching and deterministic precedence as
// fetchAppPolicy.
//
// Two finding types:
//   mandatory_missing  — mandatory policy entry not matched by any app on a device.
//   unapproved_present — installed app matched by an unapproved policy entry.
//
// Route: GET /admin/tenants/{tenantID}/app-policy-drift

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
)

// appRow is one device_apps row, as loaded by TenantAppPolicyDriftHandler.
type appRow struct {
	DeviceID       string
	Name           string
	BundleID       string
	TeamID         string
	Version        string
	IdentifierKind string
}

// mandatoryPolicySatisfiedDrift reports whether ANY app installed on this
// device matches every populated identity field in the given mandatory policy
// (case-insensitive). Each mandatory policy is tested independently against
// the full per-device app inventory — not against a single first-resolved
// policy per app — so a mandatory policy sharing an identity key with
// another (overlapping) policy is never falsely reported missing just
// because that other policy resolved first for the installed app (PAT-1147,
// sibling of the posture.go bug).
//
// Deliberately does NOT check platform: callers pass only policies returned by
// effectiveTenantPolicies, where platform mismatch and exact overrides have
// already been resolved before absence is considered.
func mandatoryPolicySatisfiedDrift(p tenantPolicy, apps []appRow, deviceOS string) bool {
	for _, a := range apps {
		if policyMatchesInstalledApp(p, installedAppPolicyIdentity{
			TeamID:   a.TeamID,
			BundleID: a.BundleID,
			WingetID: installedWingetID(a.BundleID, a.IdentifierKind, deviceOS),
			Name:     a.Name,
		}) {
			return true
		}
	}
	return false
}

// mandatoryVersionBelowMinimumDrift returns one match for each distinct
// mandatory-version finding. Like mandatoryPolicySatisfiedDrift, it tests
// every effective mandatory policy independently: a more-specific approved or
// unmanaged policy may control the normal per-app display resolution without
// suppressing a distinct mandatory identity that also applies to that app.
//
// effectiveTenantPolicies retains the exact-platform-before-any override for
// the same full identity tuple. The finding key deliberately excludes policy
// ID: duplicate rows that would render identically are noise, while distinct
// floors or enforcement tiers remain separate, actionable findings.
func mandatoryVersionBelowMinimumDrift(policies []tenantPolicy, apps []appRow, deviceOS string) []mandatoryVersionDriftMatch {
	seen := make(map[string]struct{})
	var matches []mandatoryVersionDriftMatch
	for _, p := range effectiveTenantPolicies(policies, deviceOS) {
		if p.Policy != "mandatory" || p.MinVersion == nil || *p.MinVersion == "" {
			continue
		}
		for _, a := range apps {
			if !policyMatchesInstalledApp(p, installedAppPolicyIdentity{
				TeamID:   a.TeamID,
				BundleID: a.BundleID,
				WingetID: installedWingetID(a.BundleID, a.IdentifierKind, deviceOS),
				Name:     a.Name,
			}) || compareVersions(a.Version, *p.MinVersion) >= 0 {
				continue
			}
			key := strings.Join([]string{a.Name, a.BundleID, a.Version, *p.MinVersion, p.EnforcementTier}, "\x00")
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			matches = append(matches, mandatoryVersionDriftMatch{Policy: p, App: a})
		}
	}
	return matches
}

type mandatoryVersionDriftMatch struct {
	Policy tenantPolicy
	App    appRow
}

type appPolicyDriftFinding struct {
	DeviceID         string    `json:"device_id"`
	Hostname         string    `json:"hostname"`
	DriftType        string    `json:"drift_type"` // mandatory_missing|unapproved_present|version_below_minimum
	AppName          string    `json:"app_name"`
	Identifier       string    `json:"identifier"` // bundle_id or ""
	Policy           string    `json:"policy"`
	EnforcementTier  string    `json:"enforcement_tier"`
	LastSeen         time.Time `json:"device_last_seen"`
	InstalledVersion string    `json:"installed_version"`
	MinVersion       string    `json:"min_version"`
	SoftwareKey      string    `json:"software_key"` // PAT-1878: stable lifecycle identity
}

// TenantAppPolicyDriftHandler returns per-device drift findings for a tenant.
//
// GET /admin/tenants/{tenantID}/app-policy-drift
// 200 { "findings": [...], "mandatory_missing": N, "unapproved_present": N }
func TenantAppPolicyDriftHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "app_policy_drift")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		// -- Load tenant_app_policies ----------------------------------------
		policyRows, err := pool.Query(r.Context(), `
			SELECT id, team_id, bundle_id, winget_id, name, platform, policy, enforcement_tier, min_version, source
			FROM effective_tenant_app_policies($1::uuid)
			WHERE tenant_id = $1::uuid
			  AND policy IN ('mandatory', 'approved', 'unapproved', 'unmanaged')
		`, tenantID)
		if err != nil {
			logger.Error("query app policies", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer policyRows.Close()

		var policies []tenantPolicy
		for policyRows.Next() {
			var p tenantPolicy
			if err := policyRows.Scan(&p.ID, &p.TeamID, &p.BundleID, &p.WingetID, &p.Name, &p.Platform, &p.Policy, &p.EnforcementTier, &p.MinVersion, &p.Source); err != nil {
				logger.Error("scan policy row", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			policies = append(policies, p)
		}
		if err := policyRows.Err(); err != nil {
			logger.Error("policies rows error", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		policyRows.Close()

		if len(policies) == 0 {
			// No configured policies, so no drift is possible.
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"findings":              []appPolicyDriftFinding{},
				"mandatory_missing":     0,
				"unapproved_present":    0,
				"version_below_minimum": 0,
			})
			return
		}

		// -- Load devices + their apps ----------------------------------------
		type deviceRow struct {
			ID       string
			Hostname string
			OS       string
			LastSeen time.Time
		}

		deviceQuery, err := pool.Query(r.Context(), `
			SELECT id::text, COALESCE(hostname, ''), COALESCE(os, ''),
			       COALESCE(last_seen, to_timestamp(0))
			FROM devices
			WHERE tenant_id = $1::uuid
		`, tenantID)
		if err != nil {
			logger.Error("query devices", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer deviceQuery.Close()

		var devices []deviceRow
		for deviceQuery.Next() {
			var d deviceRow
			if err := deviceQuery.Scan(&d.ID, &d.Hostname, &d.OS, &d.LastSeen); err != nil {
				logger.Error("scan device row", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			devices = append(devices, d)
		}
		if err := deviceQuery.Err(); err != nil {
			logger.Error("devices rows error", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		deviceQuery.Close()

		if len(devices) == 0 {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"findings":              []appPolicyDriftFinding{},
				"mandatory_missing":     0,
				"unapproved_present":    0,
				"version_below_minimum": 0,
			})
			return
		}

		// Collect device IDs for the apps query.
		deviceIDs := make([]string, len(devices))
		deviceByID := map[string]deviceRow{}
		for i, d := range devices {
			deviceIDs[i] = d.ID
			deviceByID[d.ID] = d
		}

		appQuery, err := pool.Query(r.Context(), `
			SELECT device_id::text, name, COALESCE(identifier,''), COALESCE(team_id,''), COALESCE(version,''), COALESCE(identifier_kind,'')
			FROM device_apps
			WHERE device_id = ANY($1::uuid[])
		`, deviceIDs)
		if err != nil {
			logger.Error("query device apps", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer appQuery.Close()

		// Group apps by device ID.
		appsByDevice := map[string][]appRow{}
		for appQuery.Next() {
			var a appRow
			if err := appQuery.Scan(&a.DeviceID, &a.Name, &a.BundleID, &a.TeamID, &a.Version, &a.IdentifierKind); err != nil {
				logger.Error("scan app row", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			appsByDevice[a.DeviceID] = append(appsByDevice[a.DeviceID], a)
		}
		if err := appQuery.Err(); err != nil {
			logger.Error("apps rows error", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// -- Build policy index for O(1) identity lookup ------------------------
		policyIndex := buildTenantPolicyIndex(policies)

		// -- Compute drift per device ------------------------------------------
		var findings []appPolicyDriftFinding
		mandatoryMissing := 0
		unapprovedPresent := 0
		versionBelowMin := 0

		for _, dev := range devices {
			apps := appsByDevice[dev.ID]

			for _, a := range apps {
				p, matched := policyIndex.resolveAppPolicy(a.TeamID, a.BundleID, a.IdentifierKind, a.Name, dev.OS)
				if !matched {
					continue
				}
				if p.Policy == "unapproved" {
					findings = append(findings, appPolicyDriftFinding{
						DeviceID:        dev.ID,
						Hostname:        dev.Hostname,
						DriftType:       "unapproved_present",
						AppName:         a.Name,
						Identifier:      a.BundleID,
						Policy:          "unapproved",
						EnforcementTier: p.EnforcementTier,
						LastSeen:        dev.LastSeen,
						SoftwareKey:     "unapproved_present:" + strconv.FormatInt(p.ID, 10),
					})
					unapprovedPresent++
				}
			}

			// Minimum-version drift is intentionally independent from the single
			// policy selected above for unapproved-present display. A different,
			// effective mandatory identity can match the same installed app and
			// still require a version floor.
			for _, match := range mandatoryVersionBelowMinimumDrift(policies, apps, dev.OS) {
				findings = append(findings, appPolicyDriftFinding{
					DeviceID:         dev.ID,
					Hostname:         dev.Hostname,
					DriftType:        "version_below_minimum",
					AppName:          match.App.Name,
					Identifier:       match.App.BundleID,
					Policy:           match.Policy.Policy,
					EnforcementTier:  match.Policy.EnforcementTier,
					LastSeen:         dev.LastSeen,
					InstalledVersion: match.App.Version,
					MinVersion:       *match.Policy.MinVersion,
					SoftwareKey:      "version_below_minimum:" + strconv.FormatInt(match.Policy.ID, 10),
				})
				versionBelowMin++
			}

			// mandatory_missing: effective mandatory policies not matched by any app
			// on this device. Each identity is resolved exact-platform-before-any,
			// then each surviving mandatory policy is tested independently against the
			// device's full app inventory (mandatoryPolicySatisfiedDrift) rather than
			// against a single first-resolved policy per app, so an overlapping
			// policy on the same app can't mask this one as missing (PAT-1147).
			for _, p := range effectiveTenantPolicies(policies, dev.OS) {
				if p.Policy != "mandatory" {
					continue
				}
				if mandatoryPolicySatisfiedDrift(p, apps, dev.OS) {
					continue
				}
				name := ""
				if p.Name != nil {
					name = *p.Name
				}
				bundleID := ""
				if p.BundleID != nil {
					bundleID = *p.BundleID
				}
				findings = append(findings, appPolicyDriftFinding{
					DeviceID:        dev.ID,
					Hostname:        dev.Hostname,
					DriftType:       "mandatory_missing",
					AppName:         name,
					Identifier:      bundleID,
					Policy:          "mandatory",
					EnforcementTier: p.EnforcementTier,
					LastSeen:        dev.LastSeen,
					SoftwareKey:     "mandatory_missing:" + strconv.FormatInt(p.ID, 10),
				})
				mandatoryMissing++
			}
		}

		// Sort: unapproved_present first, then mandatory_missing; within each, by hostname.
		sort.Slice(findings, func(i, j int) bool {
			if findings[i].DriftType != findings[j].DriftType {
				return findings[i].DriftType > findings[j].DriftType // unapproved before mandatory
			}
			if findings[i].Hostname != findings[j].Hostname {
				return findings[i].Hostname < findings[j].Hostname
			}
			return findings[i].AppName < findings[j].AppName
		})

		if findings == nil {
			findings = []appPolicyDriftFinding{}
		}

		logger.Info("app policy drift computed",
			"tenant_id", tenantID,
			"devices", len(devices),
			"mandatory_missing", mandatoryMissing,
			"unapproved_present", unapprovedPresent,
			"version_below_minimum", versionBelowMin,
		)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"findings":              findings,
			"mandatory_missing":     mandatoryMissing,
			"unapproved_present":    unapprovedPresent,
			"version_below_minimum": versionBelowMin,
		})
	}
}

// compareVersions compares two dot-separated version strings.
// Returns negative if a < b, zero if a == b, positive if a > b.
// Missing trailing segments are treated as zero (so "1.2" == "1.2.0").
// Non-numeric segments fall back to lexicographic comparison.
// Returns 0 if either input is empty, so an unknown installed version is
// never reported below the floor.
func compareVersions(a, b string) int {
	if a == "" || b == "" {
		return 0
	}
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")
	max := len(aParts)
	if len(bParts) > max {
		max = len(bParts)
	}
	for i := 0; i < max; i++ {
		aStr, bStr := "0", "0"
		if i < len(aParts) && aParts[i] != "" {
			aStr = aParts[i]
		}
		if i < len(bParts) && bParts[i] != "" {
			bStr = bParts[i]
		}
		aNum, aErr := strconv.Atoi(aStr)
		bNum, bErr := strconv.Atoi(bStr)
		if aErr == nil && bErr == nil {
			if aNum != bNum {
				return aNum - bNum
			}
		} else {
			if aStr != bStr {
				if aStr < bStr {
					return -1
				}
				return 1
			}
		}
	}
	return 0
}
