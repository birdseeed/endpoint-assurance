package cpepropose

import (
	"context"
	"fmt"
	"regexp"
)

// Browser web-app wrappers (PAT-2138 re-review, P1) are never proposed.
// A Chromium browser or Safari installs a small .app for each site a user
// "installs" as an app: "Acme Corp HR Portal", "Jira - acme.atlassian.net".
// It is signed as the browser (Google's or Microsoft's Team ID), names one
// customer's intranet, and is not a product any CPE describes. It is
// recognised by the browser's app-shim bundle identifier or by the folder
// the browser creates for its apps:
//
//	Chrome   com.google.Chrome[.beta|.dev|.canary].app.<id>   ~/Applications/Chrome[ Beta| Dev| Canary] Apps.localized/
//	Edge     com.microsoft.edgemac[.Beta|.Dev|.Canary].app.<id> ~/Applications/Edge[ Beta| Dev| Canary] Apps.localized/
//	Brave    com.brave.Browser[.beta|.nightly].app.<id>        ~/Applications/Brave Browser[ Beta| Nightly] Apps.localized/
//	Chromium org.chromium.Chromium.app.<id>                    ~/Applications/Chromium Apps.localized/
//	Vivaldi  com.vivaldi.Vivaldi.app.<id>                      ~/Applications/Vivaldi Apps.localized/
//	Safari   com.apple.Safari.WebApp.<UUID>                    (macOS 14 "Add to Dock")
//
// patched-api-01 had no such row on 2026-09-25 (read-only SELECT over
// device_apps identifiers and paths), so these shapes are the browsers'
// documented ones, pinned in TestIsWebAppWrapper. Windows installs of the
// same wrappers arrive as uninstall entries whose shape is not yet pinned
// against real inventory; that is a known gap, and the two-tenant outbound
// rule still keeps a single customer's wrapper on the platform.
const (
	webAppIdentifierPattern = `^(com\.google\.Chrome(\.beta|\.dev|\.canary)?|com\.microsoft\.edgemac(\.Beta|\.Dev|\.Canary)?|com\.brave\.Browser(\.beta|\.nightly)?|org\.chromium\.Chromium|com\.vivaldi\.Vivaldi)\.app\.|^com\.apple\.Safari\.WebApp\.`
	webAppPathPattern       = `/(Chrome|Chrome Beta|Chrome Dev|Chrome Canary|Edge|Edge Beta|Edge Dev|Edge Canary|Brave Browser|Brave Browser Beta|Brave Browser Nightly|Chromium|Vivaldi) Apps(\.localized)?/`
)

var (
	webAppIdentifier = regexp.MustCompile(webAppIdentifierPattern)
	webAppPath       = regexp.MustCompile(webAppPathPattern)
)

// IsWebAppWrapper reports whether an installed app is a browser web-app
// wrapper, by its bundle identifier or install path.
func IsWebAppWrapper(identifier, path string) bool {
	return webAppIdentifier.MatchString(identifier) || webAppPath.MatchString(path)
}

// webAppWrapperSQL is IsWebAppWrapper over device_apps alias da, with the
// two patterns as parameters $a and $b (Postgres ARE accepts both).
func webAppWrapperSQL(a, b string) string {
	return fmt.Sprintf(`(COALESCE(da.identifier, '') ~ %s OR COALESCE(da.path, '') ~ %s)`, a, b)
}

// DropWebAppWrappers removes from names every name that device reports as a
// browser web-app wrapper, so ingest never proposes one.
func DropWebAppWrappers(ctx context.Context, q DB, deviceID string, names []string) ([]string, error) {
	if len(names) == 0 {
		return names, nil
	}
	rows, err := q.Query(ctx, `
		SELECT DISTINCT da.name FROM device_apps da
		WHERE da.device_id = $1::uuid AND da.name = ANY($2::text[]) AND `+webAppWrapperSQL("$3", "$4"),
		deviceID, names, webAppIdentifierPattern, webAppPathPattern)
	if err != nil {
		return nil, fmt.Errorf("find web-app wrappers: %w", err)
	}
	wrappers := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return nil, err
		}
		wrappers[n] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := names[:0:0]
	for _, n := range names {
		if !wrappers[n] {
			out = append(out, n)
		}
	}
	return out, nil
}
