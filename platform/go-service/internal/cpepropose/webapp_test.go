package cpepropose

import "testing"

// Browser web-app wrappers are recognised by the browsers' own shapes; real
// browsers and vendor apps (the prod rows from patched-api-01, 2026-09-25)
// are not.
func TestIsWebAppWrapper(t *testing.T) {
	cases := []struct {
		identifier, path string
		want             bool
	}{
		{"com.google.Chrome.app.ahiigpfcghkbjfcibpojancebdfjmoop", "/Users/a/Applications/Chrome Apps.localized/Acme Corp HR Portal.app", true},
		{"com.google.Chrome.canary.app.abcdefghijklmnopabcdefghijklmnop", "", true},
		{"com.microsoft.edgemac.app.pnibofkfjkhbdfahlpfkdbnbokbpeloi", "/Users/a/Applications/Edge Apps.localized/Jira - acme.atlassian.net.app", true},
		{"com.brave.Browser.app.abcdefghijklmnopabcdefghijklmnop", "", true},
		{"org.chromium.Chromium.app.abcdefghijklmnopabcdefghijklmnop", "", true},
		{"com.apple.Safari.WebApp.3F2504E0-4F89-11D3-9A0C-0305E82C3301", "/Users/a/Applications/Acme Intranet.app", true},
		{"", "/Users/a/Applications/Chrome Apps.localized/Acme.app", true}, // path alone
		{"", "/Users/a/Applications/Brave Browser Apps.localized/Acme.app", true},
		// Real apps seen on patched-api-01.
		{"com.google.Chrome", "/Applications/Google Chrome.app", false},
		{"com.microsoft.edgemac", "/Applications/Microsoft Edge.app", false},
		{"com.google.drivefs.shortcuts.docs", "/Applications/Google Docs.app", false},
		{"com.microsoft.openxml.excel.app", "/Applications/Microsoft PowerPoint.app/Contents/SharedSupport/Open XML for Excel.app", false},
		{"com.google.GeminiMacOS.launcher", "/Applications/Gemini.app/Contents/Helpers/GeminiAppLauncher.app", false},
		{"com.apple.Safari", "/Applications/Safari.app", false},
	}
	for _, tc := range cases {
		if got := IsWebAppWrapper(tc.identifier, tc.path); got != tc.want {
			t.Errorf("IsWebAppWrapper(%q, %q) = %v, want %v", tc.identifier, tc.path, got, tc.want)
		}
	}
}
