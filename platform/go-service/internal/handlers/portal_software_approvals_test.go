package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestDecodeStrictJSONRejectsKeyVariants(t *testing.T) {
	good := `{"state":"approved","reason":"ok","items":[{"type":"application","platform":"macos","identifier":"com.x","team_id":"ABCDE12345"}]}`
	var req approvalWriteRequest
	if err := decodeStrictJSON([]byte(good), &req); err != nil {
		t.Fatalf("valid body refused: %v", err)
	}
	if req.State != "approved" || len(req.Items) != 1 || *req.Items[0].TeamID != "ABCDE12345" {
		t.Fatalf("decoded = %+v", req)
	}

	for name, body := range map[string]string{
		"upper-case key":         `{"STATE":"approved","items":[]}`,
		"mixed-case key":         `{"State":"approved","items":[]}`,
		"long s fold":            `{"ſtate":"approved","items":[]}`,
		"kelvin fold in item":    `{"state":"approved","items":[{"type":"application","platform":"macos","identifier":"com.x","team_id":"ABCDE12345","K":"x"}]}`,
		"case variant in item":   `{"state":"approved","items":[{"TYPE":"application"}]}`,
		"unknown key":            `{"state":"approved","items":[],"tenant_id":"x"}`,
		"duplicate key":          `{"state":"approved","state":"unapproved","items":[]}`,
		"duplicate item key":     `{"state":"approved","items":[{"type":"application","type":"browser_extension"}]}`,
		"trailing object":        `{"state":"approved","items":[]}{}`,
		"trailing garbage":       `{"state":"approved","items":[]} x`,
		"empty":                  ``,
		"not an object for item": `{"state":"approved","items":["x"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			var r approvalWriteRequest
			if err := decodeStrictJSON([]byte(body), &r); err == nil {
				t.Fatalf("accepted %s", body)
			}
		})
	}
}

func strp(s string) *string { return &s }

func TestValidateApprovalRequest(t *testing.T) {
	app := approvalItem{Type: "application", Platform: strp("macos"), Identifier: strp(" com.Example.App "), TeamID: strp("abcde12345")}
	products, reason, status, verr := validateApprovalRequest(approvalWriteRequest{State: "approved", Items: []approvalItem{app}, Reason: strp("  why  ")})
	if verr != nil {
		t.Fatalf("valid request refused: %d %+v", status, verr)
	}
	if products[0].Key != "application:macos:com.example.app:ABCDE12345" || products[0].Identifier != "com.Example.App" {
		t.Fatalf("product = %+v", products[0])
	}
	if reason == nil || *reason != "why" {
		t.Fatalf("reason = %v", reason)
	}
	if _, reason, _, _ := validateApprovalRequest(approvalWriteRequest{State: "approved", Items: []approvalItem{app}, Reason: strp("   ")}); reason != nil {
		t.Fatalf("blank reason kept as %q", *reason)
	}

	over := make([]approvalItem, ApprovalMaxItems+1)
	for i := range over {
		over[i] = approvalItem{Type: "browser_extension", Browser: strp("chrome"), ExtensionID: strp(fmt.Sprintf("ext%d", i))}
	}
	cases := []struct {
		name   string
		req    approvalWriteRequest
		status int
		code   string
	}{
		{"bad state", approvalWriteRequest{State: "mandatory", Items: []approvalItem{app}}, http.StatusBadRequest, "invalid_request"},
		{"no items", approvalWriteRequest{State: "approved"}, http.StatusBadRequest, "invalid_request"},
		{"over cap", approvalWriteRequest{State: "approved", Items: over}, http.StatusBadRequest, "too_many_items"},
		{"long reason", approvalWriteRequest{State: "approved", Items: []approvalItem{app}, Reason: strp(strings.Repeat("é", ApprovalMaxReasonChars+1))}, http.StatusBadRequest, "invalid_request"},
		{"name only", approvalWriteRequest{State: "approved", Items: []approvalItem{{Type: "application", Platform: strp("windows")}}}, http.StatusUnprocessableEntity, "name_only"},
		{"bad team id", approvalWriteRequest{State: "approved", Items: []approvalItem{{Type: "application", Platform: strp("macos"), Identifier: strp("x"), TeamID: strp("short")}}}, http.StatusBadRequest, "invalid_request"},
		{"control chars", approvalWriteRequest{State: "approved", Items: []approvalItem{{Type: "application", Platform: strp("windows"), Identifier: strp("a\nb")}}}, http.StatusBadRequest, "invalid_request"},
		{"bad browser", approvalWriteRequest{State: "approved", Items: []approvalItem{{Type: "browser_extension", Browser: strp("opera"), ExtensionID: strp("x")}}}, http.StatusBadRequest, "invalid_request"},
		{"bad extension id", approvalWriteRequest{State: "approved", Items: []approvalItem{{Type: "browser_extension", Browser: strp("chrome"), ExtensionID: strp("a b")}}}, http.StatusBadRequest, "invalid_request"},
		{"duplicate", approvalWriteRequest{State: "approved", Items: []approvalItem{app, app}}, http.StatusBadRequest, "invalid_request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, status, verr := validateApprovalRequest(tc.req)
			if verr == nil || status != tc.status || verr.Error != tc.code {
				t.Fatalf("got %d %+v, want %d %s", status, verr, tc.status, tc.code)
			}
		})
	}

	safari := approvalItem{Type: "browser_extension", Browser: strp("safari"), ExtensionID: strp("com.example.app.SafariExtension")}
	if p, _, _, verr := validateApprovalRequest(approvalWriteRequest{State: "unapproved", Items: []approvalItem{safari}}); verr != nil ||
		p[0].Key != "browser_extension:safari:com.example.app.SafariExtension" {
		t.Fatalf("safari extension refused or mis-keyed: %+v %+v", p, verr)
	}

	// Exactly the cap with a reason of exactly the limit is fine.
	atCap := over[:ApprovalMaxItems]
	if _, _, _, verr := validateApprovalRequest(approvalWriteRequest{State: "unreviewed", Items: atCap, Reason: strp(strings.Repeat("é", ApprovalMaxReasonChars))}); verr != nil {
		t.Fatalf("at-cap request refused: %+v", verr)
	}
}

func TestApprovalStateMapping(t *testing.T) {
	for policy, state := range map[string]string{"": "unreviewed", "approved": "approved", "unapproved": "unapproved", "unmanaged": "ignored", "mandatory": "mandatory"} {
		if got := appPolicyToApprovalState(policy); got != state {
			t.Errorf("app %q -> %q, want %q", policy, got, state)
		}
	}
	if approvalStateToAppPolicy("ignored") != "unmanaged" || approvalStateToAppPolicy("approved") != "approved" {
		t.Error("ignored must store as unmanaged for applications")
	}
	if extPolicyToApprovalState("") != "unreviewed" || extPolicyToApprovalState("ignored") != "ignored" {
		t.Error("extension state mapping")
	}
}

// PAT-2058: Homebrew formula/cask item validation and key derivation.
func TestNormalizeApprovalItemHomebrew(t *testing.T) {
	p, ie := normalizeApprovalItem(approvalItem{Type: "homebrew_formula", Name: strp(" OpenSSL@3 "), Tap: strp("homebrew/core")})
	if ie != nil {
		t.Fatalf("valid formula item refused: %+v", ie)
	}
	if p.Type != "homebrew_formula" || p.Identifier != "openssl@3" || p.Key != "homebrew:formula:openssl@3" {
		t.Fatalf("formula product = %+v", p)
	}

	// No tap given: same key as the explicit default tap above (both
	// collapse via NormalizeHomebrewTap).
	p2, ie := normalizeApprovalItem(approvalItem{Type: "homebrew_formula", Name: strp("openssl@3")})
	if ie != nil {
		t.Fatalf("valid formula item (no tap) refused: %+v", ie)
	}
	if p2.Key != p.Key {
		t.Fatalf("default tap and no tap produced different keys: %q vs %q", p2.Key, p.Key)
	}

	cask, ie := normalizeApprovalItem(approvalItem{Type: "homebrew_cask", Name: strp("firefox"), Tap: strp("homebrew/cask")})
	if ie != nil {
		t.Fatalf("valid cask item refused: %+v", ie)
	}
	if cask.Key != "homebrew:cask:firefox" {
		t.Fatalf("cask key = %q", cask.Key)
	}

	thirdParty, ie := normalizeApprovalItem(approvalItem{Type: "homebrew_formula", Name: strp("acme-cli"), Tap: strp("acme/tools")})
	if ie != nil {
		t.Fatalf("third-party tap item refused: %+v", ie)
	}
	if thirdParty.Key != "homebrew:formula:acme/tools/acme-cli" {
		t.Fatalf("third-party tap key = %q", thirdParty.Key)
	}

	if _, ie := normalizeApprovalItem(approvalItem{Type: "homebrew_formula"}); ie == nil {
		t.Fatal("missing name accepted")
	}
	if _, ie := normalizeApprovalItem(approvalItem{Type: "homebrew_formula", Name: strp("x"), Platform: strp("macos")}); ie == nil {
		t.Fatal("platform on a homebrew item accepted")
	}
	if _, ie := normalizeApprovalItem(approvalItem{Type: "homebrew_cask", Name: strp("a\nb")}); ie == nil {
		t.Fatal("control character in name accepted")
	}
}

func TestNormalizeApprovalItemObservation(t *testing.T) {
	p, ie := normalizeApprovalItem(approvalItem{Type: "observation", IdentityKind: strp("npm_package"), Name: strp(" @Scope/Tool "), Source: strp(" Registry.Example ")})
	if ie != nil {
		t.Fatalf("valid named observation refused: %+v", ie)
	}
	if p.Key != "observation:npm_package:@scope/tool:registry.example" || p.Identifier != "@scope/tool" || p.Source != "registry.example" {
		t.Fatalf("observation product = %+v", p)
	}
	for _, item := range []approvalItem{
		{Type: "observation", IdentityKind: strp("npm_package_unidentified"), Name: strp("tool")},
		{Type: "observation", IdentityKind: strp("npm_package"), Name: strp("tool"), Platform: strp("macos")},
		{Type: "observation", IdentityKind: strp("npm_package"), Name: strp("tool\nname")},
		{Type: "observation", IdentityKind: strp("npm_package")},
	} {
		if _, ie := normalizeApprovalItem(item); ie == nil {
			t.Fatalf("invalid observation accepted: %+v", item)
		}
	}
}

// A name or tap over 256 characters must be refused here (400), not left to
// fail tenant_homebrew_policies' CHECK constraint (migration 0195) as a 500.
func TestValidateApprovalRequestHomebrewOverlongNameAndTap(t *testing.T) {
	over := strings.Repeat("x", approvalMaxHomebrewLen+1)
	atCap := strings.Repeat("x", approvalMaxHomebrewLen)

	cases := []struct {
		name string
		item approvalItem
	}{
		{"name 257 chars", approvalItem{Type: "homebrew_formula", Name: strp(over)}},
		{"tap 257 chars", approvalItem{Type: "homebrew_formula", Name: strp("openssl@3"), Tap: strp(over)}},
		{"cask name 257 chars", approvalItem{Type: "homebrew_cask", Name: strp(over)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, status, verr := validateApprovalRequest(approvalWriteRequest{State: "approved", Items: []approvalItem{tc.item}})
			if verr == nil || status != http.StatusBadRequest {
				t.Fatalf("got %d %+v, want 400 invalid_request", status, verr)
			}
		})
	}

	// Exactly at the cap (256) is fine.
	if _, ie := normalizeApprovalItem(approvalItem{Type: "homebrew_formula", Name: strp(atCap), Tap: strp(atCap)}); ie != nil {
		t.Fatalf("256-char name/tap refused: %+v", ie)
	}
}

func TestValidateApprovalRequestHomebrewBulk(t *testing.T) {
	items := []approvalItem{
		{Type: "homebrew_formula", Name: strp("openssl@3")},
		{Type: "homebrew_cask", Name: strp("firefox")},
	}
	products, _, status, verr := validateApprovalRequest(approvalWriteRequest{State: "approved", Items: items})
	if verr != nil {
		t.Fatalf("bulk homebrew request refused: %d %+v", status, verr)
	}
	if len(products) != 2 || products[0].Key == products[1].Key {
		t.Fatalf("products = %+v", products)
	}
}

func TestCSVSafe(t *testing.T) {
	for in, want := range map[string]string{"=1+1": "'=1+1", "+x": "'+x", "-x": "'-x", "@x": "'@x", "\tx": "'\tx", "plain": "plain", "": ""} {
		if got := csvSafe(in); got != want {
			t.Errorf("csvSafe(%q) = %q, want %q", in, got, want)
		}
	}
}
