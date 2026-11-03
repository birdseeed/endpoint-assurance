package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/catalogmatch"
)

// TenantAppsHandler returns an aggregated view of all apps installed across the
// fleet for a given tenant: per-app device counts, version spread, whether an
// update is available in the catalog, and the current update-enabled policy.
//
// Route: GET /admin/tenants/{tenantID}/apps  (internal listener :8081)
//
// Response shape:
//
//	{
//	  "tenant_id": "...",
//	  "apps": [
//	    {
//	      "id": "com.google.Chrome",
//	      "name": "Google Chrome",
//	      "platform": "macos",
//	      "device_count": 5,
//	      "version_spread": [
//	        { "version": "126.0.6478.127", "device_count": 4 },
//	        { "version": "125.0.6422.142", "device_count": 1 }
//	      ],
//	      "update_available": true,
//	      "target_version": "126.0.6478.127",
//	      "catalog_label": "googlechrome",
//	      "evidence_at": "2026-08-04T08:00:00Z",
//	      "evidence_state": "update_available",
//	      "devices": [
//	        {"device_id":"...","hostname":"mac-01","version":"125.0.6422.142","last_seen":"2026-08-04T08:00:00Z","update_state":"update_available"}
//	      ],
//	      "updates_enabled": true
//	    }
//	  ]
//	}

// tenantAppVersionEntry is one entry in version_spread.
type tenantAppVersionEntry struct {
	Version     string `json:"version"`
	DeviceCount int    `json:"device_count"`
}

// tenantAppDeviceEntry is one device's evidence for an installed app.
type tenantAppDeviceEntry struct {
	DeviceID    string    `json:"device_id"`
	Hostname    string    `json:"hostname"`
	Version     string    `json:"version"`
	LastSeen    time.Time `json:"last_seen"`
	UpdateState string    `json:"update_state"`
}

// tenantAppEntry is one app row in the response.
type tenantAppEntry struct {
	ID              string                  `json:"id"`
	Name            string                  `json:"name"`
	Platform        string                  `json:"platform"`
	DeviceCount     int                     `json:"device_count"`
	VersionSpread   []tenantAppVersionEntry `json:"version_spread"`
	UpdateAvailable bool                    `json:"update_available"`
	UpdatesEnabled  bool                    `json:"updates_enabled"`
	TargetVersion   string                  `json:"target_version"`
	CatalogLabel    string                  `json:"catalog_label"`
	EvidenceAt      *time.Time              `json:"evidence_at"`
	EvidenceState   string                  `json:"evidence_state"`
	Devices         []tenantAppDeviceEntry  `json:"devices"`
}

// tenantAppsResp is the top-level response.
type tenantAppsResp struct {
	TenantID string           `json:"tenant_id"`
	Apps     []tenantAppEntry `json:"apps"`
}

const (
	tenantAppStateUpdateAvailable     = "update_available"
	tenantAppStateCurrent             = "current"
	tenantAppStateEvidenceUnavailable = "evidence_unavailable"
	tenantAppStateNotCatalogued       = "not_catalogued"
)

type tenantAppCatalogEntry struct {
	label          string
	name           string
	platform       string
	verifiedSigner *string
	latestVersion  string
}

type tenantAppInstalledDevice struct {
	deviceID string
	hostname string
	name     string
	version  string
	teamID   string
	lastSeen time.Time
}

// tenantAppCatalogMatches enforces product identity before signer identity.
// A shared signer can sign many unrelated products, so signer equality only
// narrows a non-empty bidirectional product-name match; it can never create a
// match by itself. The rule, including the helper and sub-app backstop for
// stale rows that pre-date PAT-594's extractor suppression, is shared with the
// version sprawl report in internal/catalogmatch (PAT-2509).
func tenantAppCatalogMatches(identifier string, installed tenantAppInstalledDevice, catalog tenantAppCatalogEntry) bool {
	return catalogmatch.ProductMatches(identifier, installed.name, installed.teamID, catalog.name, catalog.verifiedSigner)
}

func tenantAppDeviceState(version, targetVersion string, catalogued bool) string {
	if !catalogued {
		return tenantAppStateNotCatalogued
	}
	if strings.TrimSpace(version) == "" || strings.TrimSpace(targetVersion) == "" {
		return tenantAppStateEvidenceUnavailable
	}
	// A catalogue target is a minimum verified target, not an exact-version
	// pin. An installed version newer than the catalogue must never be offered
	// a backwards "update". compareVersions also handles numeric segments such
	// as 150 > 126 without lexicographic ordering errors.
	if compareVersions(version, targetVersion) < 0 {
		return tenantAppStateUpdateAvailable
	}
	return tenantAppStateCurrent
}

func tenantAppEvidenceState(devices []tenantAppDeviceEntry, catalogued bool) string {
	if !catalogued {
		return tenantAppStateNotCatalogued
	}
	state := tenantAppStateCurrent
	for _, device := range devices {
		switch device.UpdateState {
		case tenantAppStateUpdateAvailable:
			return tenantAppStateUpdateAvailable
		case tenantAppStateEvidenceUnavailable, tenantAppStateNotCatalogued:
			state = tenantAppStateEvidenceUnavailable
		}
	}
	return state
}

// TenantAppsHandler returns the aggregated app-update view for a tenant.
func TenantAppsHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "tenant_apps")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		// Verify tenant exists and fetch the fleet default.
		var defaultEnabled bool
		err := pool.QueryRow(r.Context(),
			`SELECT app_updates_default_enabled FROM tenants WHERE id = $1::uuid AND revoked_at IS NULL`,
			tenantID,
		).Scan(&defaultEnabled)
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}
		if err != nil {
			logger.Error("query tenant failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		type appKey struct {
			identifier string
			platform   string
		}
		type rawApp struct {
			key       appKey
			nameCount map[string]int
			devices   []tenantAppInstalledDevice
		}

		// Select one current evidence row per app/device. PAT-808 normally keeps
		// device_apps pruned already; ROW_NUMBER is a defensive guard for stale
		// historical duplicates and ensures one device cannot be counted twice.
		const inventoryQuery = `
WITH ranked AS (
    SELECT
        da.identifier,
        da.name,
        COALESCE(da.version, '') AS version,
        COALESCE(da.team_id, '') AS team_id,
        da.device_id::text,
        COALESCE(d.hostname, d.computer_name, '') AS hostname,
        CASE WHEN d.os ILIKE 'windows%' THEN 'windows' ELSE 'macos' END AS platform,
        da.last_seen,
        ROW_NUMBER() OVER (
            PARTITION BY da.identifier,
                CASE WHEN d.os ILIKE 'windows%' THEN 'windows' ELSE 'macos' END,
                da.device_id
            ORDER BY da.last_seen DESC, da.id DESC
        ) AS evidence_rank
    FROM device_apps da
    JOIN devices d ON d.id = da.device_id
    WHERE d.tenant_id = $1::uuid
)
SELECT identifier, name, version, team_id, device_id, hostname, platform, last_seen
FROM ranked
WHERE evidence_rank = 1
ORDER BY identifier, platform, hostname, device_id
`

		rows, err := pool.Query(r.Context(), inventoryQuery, tenantID)
		if err != nil {
			logger.Error("query tenant app inventory failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		appMap := make(map[appKey]*rawApp)
		for rows.Next() {
			var identifier, name, version, teamID, deviceID, hostname, platform string
			var lastSeen time.Time
			if err := rows.Scan(&identifier, &name, &version, &teamID, &deviceID, &hostname, &platform, &lastSeen); err != nil {
				logger.Error("scan tenant app inventory row failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			k := appKey{identifier, platform}
			app := appMap[k]
			if app == nil {
				app = &rawApp{key: k, nameCount: make(map[string]int)}
				appMap[k] = app
			}
			app.nameCount[name]++
			app.devices = append(app.devices, tenantAppInstalledDevice{
				deviceID: deviceID,
				hostname: hostname,
				name:     name,
				version:  version,
				teamID:   teamID,
				lastSeen: lastSeen,
			})
		}
		if err := rows.Err(); err != nil {
			logger.Error("iterate tenant app inventory rows failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		rows.Close()

		catalogRows, err := pool.Query(r.Context(), `
SELECT label, name, platform, verified_signer IS NOT NULL,
       COALESCE(verified_signer, ''), latest_version
FROM app_catalog_entries
ORDER BY verified_at DESC, updated_at DESC, label ASC`)
		if err != nil {
			logger.Error("query app catalog failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer catalogRows.Close()
		catalog := make([]tenantAppCatalogEntry, 0)
		for catalogRows.Next() {
			var c tenantAppCatalogEntry
			var hasSigner bool
			var signer string
			if err := catalogRows.Scan(&c.label, &c.name, &c.platform, &hasSigner, &signer, &c.latestVersion); err != nil {
				logger.Error("scan app catalog row failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if hasSigner {
				signerCopy := signer
				c.verifiedSigner = &signerCopy
			}
			catalog = append(catalog, c)
		}
		if err := catalogRows.Err(); err != nil {
			logger.Error("iterate app catalog rows failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		catalogRows.Close()

		policyRows, err := pool.Query(r.Context(), `
SELECT identifier, platform, enabled
FROM tenant_app_update_policies
WHERE tenant_id = $1::uuid`, tenantID)
		if err != nil {
			logger.Error("query tenant app update policies failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer policyRows.Close()
		policies := make(map[appKey]bool)
		for policyRows.Next() {
			var identifier, platform string
			var enabled bool
			if err := policyRows.Scan(&identifier, &platform, &enabled); err != nil {
				logger.Error("scan tenant app update policy failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			policies[appKey{identifier, platform}] = enabled
		}
		if err := policyRows.Err(); err != nil {
			logger.Error("iterate tenant app update policies failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		policyRows.Close()

		apps := make([]tenantAppEntry, 0, len(appMap))
		for _, app := range appMap {
			name := ""
			nameCount := -1
			for candidate, count := range app.nameCount {
				if count > nameCount || (count == nameCount && candidate < name) {
					name, nameCount = candidate, count
				}
			}

			var match *tenantAppCatalogEntry
			for i := range catalog {
				wantPlatform := "macOS"
				if app.key.platform == "windows" {
					wantPlatform = "Windows"
				}
				if catalog[i].platform != wantPlatform {
					continue
				}
				for _, device := range app.devices {
					if tenantAppCatalogMatches(app.key.identifier, device, catalog[i]) {
						match = &catalog[i]
						break
					}
				}
				if match != nil {
					break
				}
			}

			entry := tenantAppEntry{
				ID:             app.key.identifier,
				Name:           name,
				Platform:       app.key.platform,
				DeviceCount:    len(app.devices),
				VersionSpread:  []tenantAppVersionEntry{},
				Devices:        []tenantAppDeviceEntry{},
				UpdatesEnabled: defaultEnabled,
			}
			if enabled, ok := policies[app.key]; ok {
				entry.UpdatesEnabled = enabled
			}
			catalogued := match != nil
			if catalogued {
				entry.TargetVersion = match.latestVersion
				entry.CatalogLabel = match.label
			}

			versionCounts := make(map[string]int)
			for _, installed := range app.devices {
				versionCounts[installed.version]++
				deviceCatalogued := catalogued && tenantAppCatalogMatches(app.key.identifier, installed, *match)
				state := tenantAppDeviceState(installed.version, entry.TargetVersion, deviceCatalogued)
				entry.Devices = append(entry.Devices, tenantAppDeviceEntry{
					DeviceID:    installed.deviceID,
					Hostname:    installed.hostname,
					Version:     installed.version,
					LastSeen:    installed.lastSeen,
					UpdateState: state,
				})
				if entry.EvidenceAt == nil || installed.lastSeen.After(*entry.EvidenceAt) {
					seen := installed.lastSeen
					entry.EvidenceAt = &seen
				}
			}
			for version, count := range versionCounts {
				entry.VersionSpread = append(entry.VersionSpread, tenantAppVersionEntry{Version: version, DeviceCount: count})
			}
			sort.Slice(entry.VersionSpread, func(i, j int) bool {
				if entry.VersionSpread[i].DeviceCount != entry.VersionSpread[j].DeviceCount {
					return entry.VersionSpread[i].DeviceCount > entry.VersionSpread[j].DeviceCount
				}
				return entry.VersionSpread[i].Version < entry.VersionSpread[j].Version
			})
			entry.EvidenceState = tenantAppEvidenceState(entry.Devices, catalogued)
			entry.UpdateAvailable = entry.EvidenceState == tenantAppStateUpdateAvailable
			apps = append(apps, entry)
		}
		sort.Slice(apps, func(i, j int) bool {
			if apps[i].UpdateAvailable != apps[j].UpdateAvailable {
				return apps[i].UpdateAvailable
			}
			if apps[i].DeviceCount != apps[j].DeviceCount {
				return apps[i].DeviceCount > apps[j].DeviceCount
			}
			return apps[i].Name < apps[j].Name
		})

		logger.Info("tenant apps listed", "tenant_id", tenantID, "count", len(apps))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tenantAppsResp{
			TenantID: tenantID,
			Apps:     apps,
		})
	}
}
